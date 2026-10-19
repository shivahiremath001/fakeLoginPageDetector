"""Playwright page capture for the Fake Login Page Detector."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from playwright.async_api import (
    Browser,
    BrowserContext,
    Error as PlaywrightError,
    Page,
    Playwright,
    async_playwright,
)

from app.config import settings
from app.models import BoundingBox, FormInfo, PageSnapshot, RequestRecord
from app.utils.urls import normalize_url, resolve_action

logger = logging.getLogger(__name__)

_IGNORED_RESOURCE_TYPES = {"image", "media", "font"}
_MAX_REQUESTS = 500
_SCAN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_INTERNAL_HOST_SUFFIXES = (
    ".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa",
    ".intranet", ".corp", ".intra", ".private", ".localdomain", ".test",
    ".example", ".invalid", ".onion",
)


class UnsafeTargetError(ValueError):
    """Raised when a URL resolves to a disallowed network target."""


def _parse_http_url(url: str):
    """Parse an HTTP(S) URL and reject malformed URLs or embedded credentials."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port  # Accessing port validates its syntax and range.
    except (TypeError, ValueError) as exc:
        raise UnsafeTargetError("The URL is malformed.") from exc

    if scheme not in {"http", "https"}:
        raise UnsafeTargetError("Only HTTP and HTTPS URLs are allowed.")
    if not host:
        raise UnsafeTargetError("The URL has no hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTargetError("URLs containing credentials are not allowed.")

    return parsed, scheme, host.rstrip(".").lower(), port


async def _resolve_host_addresses(host: str, port: int) -> list[str]:
    """Resolve a hostname with a timeout and return its IP addresses."""
    try:
        literal = ipaddress.ip_address(host)
        return [str(literal)]
    except ValueError:
        pass

    try:
        records = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                host, port, type=socket.SOCK_STREAM
            ),
            timeout=max(float(settings.page_timeout_ms) / 1000.0, 1.0),
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise UnsafeTargetError("The hostname could not be resolved safely.") from exc

    addresses: list[str] = []
    for record in records:
        try:
            value = str(ipaddress.ip_address(record[4][0]))
        except (ValueError, IndexError, TypeError):
            continue
        if value not in addresses:
            addresses.append(value)

    if not addresses:
        raise UnsafeTargetError("The hostname has no usable IP addresses.")
    return addresses


def _is_public_ip(value: str) -> bool:
    """Return False for private, reserved, loopback, and mapped-private IPs."""
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global


async def _validate_public_url(url: str) -> None:
    """Strictly validate a URL, regardless of the local-demo configuration."""
    _, scheme, host, port = _parse_http_url(url)

    if (
        host == "localhost"
        or "." not in host
        or any(host.endswith(suffix) for suffix in _INTERNAL_HOST_SUFFIXES)
    ):
        raise UnsafeTargetError("Internal hostnames are blocked.")

    addresses = await _resolve_host_addresses(
        host, port or (443 if scheme == "https" else 80)
    )
    if any(not _is_public_ip(value) for value in addresses):
        raise UnsafeTargetError(
            "Private or non-public network destinations are blocked."
        )


async def _validate_target(url: str) -> None:
    """Validate URL syntax and apply public-network restrictions if configured."""
    _parse_http_url(url)

    # This switch is useful for local hackathon demos and local test pages.
    # Set FAKELD_ALLOW_PRIVATE_HOSTS=false in deployed environments.
    if settings.allow_private_hosts:
        return

    await _validate_public_url(url)


async def _validate_websocket_url(url: str) -> None:
    """Validate ws/wss destinations using equivalent HTTP(S) rules."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"ws", "wss"}:
            raise UnsafeTargetError("Only WS and WSS WebSocket URLs are allowed.")
        http_scheme = "https" if scheme == "wss" else "http"
        http_url = urlunsplit(
            (http_scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)
        )
    except ValueError as exc:
        raise UnsafeTargetError("The WebSocket URL is malformed.") from exc

    await _validate_public_url(http_url)


def _origin(url: str) -> tuple[str, str, int | None]:
    """Return a normalized origin, treating default ports consistently."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port
        if port is None:
            if scheme == "https":
                port = 443
            elif scheme == "http":
                port = 80
        return scheme, host, port
    except (TypeError, ValueError):
        return "", "", None


class PageFetcher:
    """Manage a shared Chromium browser and safely capture web pages."""

    def __init__(self) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max(1, settings.max_concurrent_scans))

    async def startup(self) -> None:
        """Start Chromium once for the application."""
        async with self._lock:
            if self._browser is not None:
                connected = getattr(self._browser, "is_connected", None)
                if connected is None or connected():
                    return

            playwright = await async_playwright().start()
            try:
                browser = await playwright.chromium.launch(headless=True)
            except Exception:
                await playwright.stop()
                raise

            self._playwright = playwright
            self._browser = browser
            logger.info("Playwright Chromium started.")

    async def shutdown(self) -> None:
        """Close the shared browser and Playwright runtime."""
        async with self._lock:
            try:
                if self._browser is not None:
                    await self._browser.close()
            finally:
                self._browser = None
                if self._playwright is not None:
                    await self._playwright.stop()
                    self._playwright = None

            logger.info("Playwright Chromium stopped.")

    @staticmethod
    def _form_info(item: dict, page_url: str) -> FormInfo:
        """Build form metadata, including normalized same-origin comparison."""
        action_raw = str(item.get("action_raw", item.get("action", "")) or "")
        action = resolve_action(action_raw, page_url)
        action_origin = _origin(action)
        page_origin = _origin(page_url)

        try:
            parsed_action = urlsplit(action)
            action_scheme = parsed_action.scheme.lower()
            action_host = (parsed_action.hostname or "").lower()
            action_port = parsed_action.port

            if action_port is None:
                action_port = {"http": 80, "https": 443}.get(action_scheme)

            default_port = {"http": 80, "https": 443}.get(action_scheme)

            action_netloc = action_host
            if action_port is not None and action_port != default_port:
                action_netloc = f"{action_host}:{action_port}"

            if action_host and action_scheme:
                action_netloc = f"{action_scheme}://{action_netloc}"
            else:
                action_netloc = ""
        except (TypeError, ValueError):
            action_netloc = ""

        box = item.get("box")
        bounding_box = BoundingBox(**box) if isinstance(box, dict) else None

        return FormInfo(
            action_raw=action_raw,
            action_resolved=action,
            action_origin=action_netloc,
            method=str(item.get("method", "get") or "get").lower(),
            has_password=bool(item.get("has_password", False)),
            hidden_fields=list(item.get("hidden_fields", [])),
            field_names=list(item.get("field_names", [])),
            bounding_box=bounding_box,
            is_cross_origin=action_origin != page_origin,
            is_http=action_origin[0] == "http",
        )

    async def fetch(self, url: str, scan_id: str) -> PageSnapshot:
        """Render a page and collect HTML, screenshot, forms, and requests."""
        if not isinstance(scan_id, str) or not _SCAN_ID_PATTERN.fullmatch(scan_id):
            raise ValueError(
                "Invalid scan_id; use 1-128 letters, digits, underscores, or hyphens."
            )

        normalized = normalize_url(url)
        if not normalized:
            return PageSnapshot(
                requested_url=str(url),
                load_error="Invalid or unsupported URL.",
            )

        try:
            await _validate_target(normalized)
        except (UnsafeTargetError, ValueError, OSError) as exc:
            return PageSnapshot(
                requested_url=normalized,
                final_url=normalized,
                load_error=str(exc),
            )

        if self._browser is None:
            try:
                await self.startup()
            except Exception as exc:
                logger.exception("Could not start Chromium.")
                return PageSnapshot(
                    requested_url=normalized,
                    final_url=normalized,
                    load_error=f"Browser startup failed: {type(exc).__name__}.",
                )
        else:
            connected = getattr(self._browser, "is_connected", None)
            if connected is not None and not connected():
                try:
                    await self.startup()
                except Exception as exc:
                    logger.exception("Could not restart Chromium.")
                    return PageSnapshot(
                        requested_url=normalized,
                        final_url=normalized,
                        load_error=f"Browser startup failed: {type(exc).__name__}.",
                    )

        assert self._browser is not None

        async with self._semaphore:
            context: BrowserContext | None = None
            page: Page | None = None
            redirect_chain: list[str] = []
            requests: list[RequestRecord] = []
            request_urls: set[str] = set()
            response_status: int | None = None
            screenshot_path: Path | None = None
            favicon_path: str | None = None

            try:
                context_options = {
                    "viewport": {
                        "width": settings.viewport_width,
                        "height": settings.viewport_height,
                    },
                    "accept_downloads": False,
                }
                # Service workers can bypass ordinary request routing.
                if not settings.allow_private_hosts:
                    context_options["service_workers"] = "block"

                context = await self._browser.new_context(**context_options)
                page = await context.new_page()
                page.set_default_navigation_timeout(settings.page_timeout_ms)
                page.set_default_timeout(settings.page_timeout_ms)
                async def guard_request(route) -> None:
                    request = route.request

                    # Validate every destination before allowing the request,
                    # including images, media, fonts, redirects, and frames.
                    if not settings.allow_private_hosts:
                        try:
                            await _validate_public_url(request.url)
                        except (UnsafeTargetError, ValueError, OSError):
                            await route.abort()
                            return

                    await route.continue_()


                # Context-level routing covers navigations and subresources,
                # including requests initiated by child frames.
                await context.route("**/*", guard_request)

                if not settings.allow_private_hosts:
                    route_web_socket = getattr(context, "route_web_socket", None)
                    if route_web_socket is None:
                        raise RuntimeError(
                            "This Playwright version cannot guard WebSocket requests. "
                            "Upgrade Playwright or keep private-host access disabled "
                            "only after verifying WebSocket routing support."
                        )

                    async def guard_websocket(websocket_route) -> None:
                        try:
                            await _validate_websocket_url(websocket_route.url)
                        except (UnsafeTargetError, ValueError, OSError):
                            await websocket_route.close(
                                code=1008,
                                reason="Blocked unsafe WebSocket destination",
                            )
                            return
                        await websocket_route.connect_to_server()

                    await route_web_socket("**/*", guard_websocket)

                def record_request(request) -> None:
                    if len(requests) >= _MAX_REQUESTS or request.url in request_urls:
                        return
                    request_urls.add(request.url)
                    try:
                        requests.append(
                            RequestRecord(
                                url=request.url,
                                method=request.method,
                                resource_type=request.resource_type,
                                origin=urlsplit(request.url).netloc.lower(),
                                has_body=request.post_data is not None,
                            )
                        )
                    except Exception:
                        logger.debug("Skipping malformed network request.")

                page.on("request", record_request)

                def record_response(response) -> None:
                    nonlocal response_status
                    request = response.request
                    if not request.is_navigation_request():
                        return

                    response_status = response.status
                    chain: list[str] = []
                    previous = request.redirected_from
                    while previous is not None:
                        chain.append(previous.url)
                        previous = previous.redirected_from

                    for redirect_url in reversed(chain):
                        if redirect_url != normalized and redirect_url not in redirect_chain:
                            redirect_chain.append(redirect_url)

                    if response.url != normalized and response.url not in redirect_chain:
                        redirect_chain.append(response.url)

                page.on("response", record_response)

                navigation_load_error: str | None = None
                try:
                    await page.goto(normalized, wait_until="domcontentloaded")
                    try:
                        await page.wait_for_load_state(
                            "networkidle",
                            timeout=settings.network_idle_cap_ms,
                        )
                    except PlaywrightError:
                        pass
                except PlaywrightError as exc:
                    if page.is_closed() or not page.url:
                        raise

                    logger.warning("Page navigation partially failed: %s", exc)
                    if "timeout" in str(exc).lower():
                        navigation_load_error = "Navigation timed out."

                final_url = page.url or normalized
                await _validate_target(final_url)

                html = await page.content()
                encoded_html = html.encode("utf-8", errors="replace")
                if len(encoded_html) > settings.max_html_bytes:
                    html = encoded_html[:settings.max_html_bytes].decode(
                        "utf-8", errors="ignore"
                    )

                title = await page.title()
                visible_text = ""
                try:
                    visible_text = await page.locator("body").inner_text(timeout=2000)
                except PlaywrightError:
                    pass

                artifact_dir = settings.artifacts_dir / scan_id
                artifact_dir.mkdir(parents=True, exist_ok=True)
                screenshot_path = artifact_dir / "page.png"

                await page.screenshot(
                    path=str(screenshot_path),
                    full_page=False,
                    animations="disabled",
                    timeout=settings.page_timeout_ms,
                )

                form_data = await page.locator("form").evaluate_all(
                    """forms => forms.map(form => {
                        const rect = form.getBoundingClientRect();
                        const fields = Array.from(
                            form.querySelectorAll('input, select, textarea')
                        );
                        return {
                            action_raw: form.getAttribute('action') || '',
                            method: (form.getAttribute('method') || 'get').toLowerCase(),
                            has_password: fields.some(
                                field => (field.type || '').toLowerCase() === 'password'
                            ),
                            hidden_fields: fields
                                .filter(field => (field.type || '').toLowerCase() === 'hidden')
                                .map(field => field.name).filter(Boolean),
                            field_names: fields
                                .filter(field => (field.type || '').toLowerCase() !== 'hidden')
                                .map(field => field.name).filter(Boolean),
                            box: {
                                x: rect.x, y: rect.y,
                                width: rect.width, height: rect.height
                            }
                        };
                    })"""
                )
                forms = [self._form_info(item, final_url) for item in form_data]

                # Favicon requests use APIRequestContext, so validate separately.
                try:
                    favicon_href = await page.locator(
                        'link[rel~="icon"]'
                    ).first.get_attribute("href", timeout=1000)
                    if favicon_href:
                        favicon_url = urljoin(final_url, favicon_href)
                        _, favicon_scheme, _, _ = _parse_http_url(favicon_url)
                        if not settings.allow_private_hosts:
                            await _validate_public_url(favicon_url)

                        response = await context.request.get(
                            favicon_url,
                            timeout=2000,
                            max_redirects=0,
                        )
                        try:
                            if response.ok:
                                content_type = response.headers.get("content-type", "")
                                if content_type.startswith("image/"):
                                    suffix = Path(urlsplit(favicon_url).path).suffix.lower()
                                    if suffix not in {
                                        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp"
                                    }:
                                        suffix = ".ico"
                                    favicon_file = artifact_dir / f"favicon{suffix}"
                                    favicon_file.write_bytes(await response.body())
                                    favicon_path = str(favicon_file)
                        finally:
                            await response.dispose()
                except Exception:
                    logger.debug("Favicon capture failed.", exc_info=True)

                logo_candidates: list[dict] = []
                element_boxes: dict[str, list[BoundingBox]] = {}
                try:
                    candidates = await page.locator("img").evaluate_all(
                        """images => images.slice(0, 30).map(img => {
                            const r = img.getBoundingClientRect();
                            return {
                                src: img.currentSrc || img.src || '',
                                alt: img.alt || '',
                                width: r.width, height: r.height, x: r.x, y: r.y
                            };
                        })"""
                    )
                    for candidate in candidates:
                        if (
                            not candidate["src"]
                            or candidate["width"] < 24
                            or candidate["height"] < 16
                            or candidate["x"] >= settings.viewport_width
                            or candidate["y"] >= settings.viewport_height
                            or candidate["x"] + candidate["width"] <= 0
                            or candidate["y"] + candidate["height"] <= 0
                        ):
                            continue
                        box = {
                            "x": candidate["x"],
                            "y": candidate["y"],
                            "width": candidate["width"],
                            "height": candidate["height"],
                        }
                        logo_candidates.append({
                            "src": candidate["src"],
                            "alt": candidate["alt"],
                            "box": box,
                        })

                    password_boxes = await page.locator(
                        "input[type=password]"
                    ).evaluate_all(
                        """items => items.slice(0, 30).map((item, i) => {
                            const r = item.getBoundingClientRect();
                            return {
                                key: String(i), x: r.x, y: r.y,
                                width: r.width, height: r.height
                            };
                        }).reduce((out, item) => {
                            out[item.key] = {
                                x: item.x, y: item.y,
                                width: item.width, height: item.height
                            };
                            return out;
                        }, {})"""
                    )
                    element_boxes = {
                        key: [BoundingBox(**box)]
                        for key, box in password_boxes.items()
                    }
                except PlaywrightError:
                    pass

                is_image_only = (
                    len(visible_text.strip()) < settings.image_only_text_chars
                    and any(
                        candidate["box"]["x"] < settings.viewport_width
                        and candidate["box"]["y"] < settings.viewport_height
                        and candidate["box"]["x"] + candidate["box"]["width"] > 0
                        and candidate["box"]["y"] + candidate["box"]["height"] > 0
                        for candidate in logo_candidates
                    )
                )

                return PageSnapshot(
                    requested_url=normalized,
                    final_url=final_url,
                    redirect_chain=redirect_chain,
                    status=response_status,
                    title=title,
                    html=html,
                    visible_text=visible_text,
                    screenshot_path=str(screenshot_path),
                    viewport={
                        "width": settings.viewport_width,
                        "height": settings.viewport_height,
                    },
                    forms=forms,
                    requests=requests,
                    favicon_path=favicon_path,
                    logo_candidates=logo_candidates,
                    element_boxes=element_boxes,
                    is_image_only=is_image_only,
                    load_error=navigation_load_error,
                )

            except Exception as exc:
                logger.exception("Page capture failed for %s", normalized)
                current_url = normalized
                if page is not None:
                    try:
                        if not page.is_closed() and page.url:
                            current_url = page.url
                    except Exception:
                        pass

                return PageSnapshot(
                    requested_url=normalized,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    status=response_status,
                    load_error=f"Page capture failed: {type(exc).__name__}.",
                    requests=requests,
                    screenshot_path=str(screenshot_path) if screenshot_path else None,
                    favicon_path=favicon_path,
                )
            finally:
                if context is not None:
                    try:
                        await context.close()
                    except Exception:
                        logger.debug("Browser context close failed.", exc_info=True)


fetcher = PageFetcher()
