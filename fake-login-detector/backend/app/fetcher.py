"""
fetcher.py — Playwright wrapper that renders pages into PageSnapshot objects.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
import socket
from typing import Protocol
from urllib.parse import urlparse, urlsplit, urlunsplit

from playwright.async_api import (
    Browser,
    Error as PlaywrightError,
    Request,
    Route,
    Response,
    TimeoutError as PlaywrightTimeoutError,
    async_playwright,
)
from playwright.async_api import Playwright

from app.config import settings
from app.models import FormInfo, PageSnapshot, RequestRecord
from app.utils.urls import normalize_url, origin_key, resolve_action

logger = logging.getLogger(__name__)

_SCAN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_INTERNAL_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".home.arpa",
    ".intranet",
    ".corp",
    ".intra",
    ".private",
    ".localdomain",
    ".test",
    ".example",
    ".invalid",
    ".onion",
)

_EXTRACT_PAGE_SCRIPT = """() => {
    const box = (element) => {
        const rect = element.getBoundingClientRect();
        return {
            x: rect.x,
            y: rect.y,
            width: rect.width,
            height: rect.height,
        };
    };
    const forms = Array.from(document.forms, (form) => ({
        action_raw: form.getAttribute("action") || "",
        method: (form.getAttribute("method") || "get").toLowerCase(),
        has_password: Boolean(form.querySelector('input[type="password"]')),
        hidden_fields: Array.from(
            form.querySelectorAll('input[type="hidden"]'),
            (input) => input.name
        ).filter(Boolean),
        field_names: Array.from(
            form.querySelectorAll('input:not([type="hidden"]), select, textarea'),
            (input) => input.name
        ).filter(Boolean),
        bounding_box: box(form),
    }));
    const password_boxes = Array.from(
        document.querySelectorAll('input[type="password"]'),
        box
    );
    const images = Array.from(document.images, (image) => ({
        src: image.currentSrc || image.src,
        box: box(image),
    })).filter((image) => image.box.width > 0 && image.box.height > 0);

    return {
        title: document.title || "",
        html: document.documentElement ? document.documentElement.outerHTML : "",
        visible_text: document.body ? document.body.innerText : "",
        forms,
        password_boxes,
        images,
        viewport: {width: innerWidth, height: innerHeight},
    };
}"""


class PageFetcher:
    """Owns one shared Chromium browser and creates an isolated context per fetch."""

    def __init__(self) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_scans)

    async def startup(self) -> None:
        """Start the shared Playwright browser. Called from FastAPI lifespan."""
        if self._browser is not None:
            return

        playwright = await async_playwright().start()
        try:
            browser = await playwright.chromium.launch(headless=True)
        except BaseException:
            await playwright.stop()
            raise

        self._playwright = playwright
        self._browser = browser
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
        logger.info("Playwright Chromium browser started")

    async def shutdown(self) -> None:
        """Close the browser and Playwright driver."""
        browser, self._browser = self._browser, None
        playwright, self._playwright = self._playwright, None

        try:
            if browser is not None:
                await browser.close()
        finally:
            if playwright is not None:
                await playwright.stop()
        logger.info("Playwright Chromium browser stopped")

    async def fetch(self, url: str, scan_id: str) -> PageSnapshot:
        """
        Navigate to a URL and return the captured page state.

        Invalid URLs and invalid artifact identifiers raise ValueError. Browser
        startup failures are raised to the caller; navigation failures are
        returned as PageSnapshot.load_error so a timed-out page can still supply
        whatever state was captured before the failure.
        """
        if self._browser is None:
            raise RuntimeError("PageFetcher.startup() must be called before fetch().")

        normalized_url = normalize_url(url)
        if normalized_url is None:
            raise ValueError("URL must be a valid HTTP or HTTPS URL.")
        if not _SCAN_ID_PATTERN.fullmatch(scan_id):
            raise ValueError("scan_id must contain only letters, digits, underscores, or hyphens.")
        if not settings.allow_private_hosts:
            await _validate_public_url(normalized_url)

        async with self._semaphore:
            return await self._fetch_page(normalized_url, scan_id)

    async def _fetch_page(self, url: str, scan_id: str) -> PageSnapshot:
        assert self._browser is not None
        viewport = {
            "width": settings.viewport_width,
            "height": settings.viewport_height,
        }
        if settings.allow_private_hosts:
            context = await self._browser.new_context(viewport=viewport)
        else:
            context = await self._browser.new_context(
                viewport=viewport,
                service_workers="block",
            )
        try:
            blocked_requests: set[str] = set()
            if not settings.allow_private_hosts:
                async def guard_request(route: Route, request: Request) -> None:
                    try:
                        await _validate_public_url(request.url)
                    except ValueError as exc:
                        try:
                            host = urlsplit(request.url).hostname or "<invalid>"
                        except ValueError:
                            host = "<invalid>"
                        blocked_requests.add(host)
                        logger.warning(
                            "Blocked browser request to %s: %s",
                            host,
                            exc,
                        )
                        await route.abort("blockedbyclient")
                        return
                    await route.continue_()

                await context.route("**/*", guard_request)
                route_web_socket = getattr(context, "route_web_socket", None)
                if not callable(route_web_socket):
                    raise RuntimeError(
                        "Private-host protection requires Playwright WebSocket routing."
                    )

                async def guard_web_socket(route: _WebSocketRoute) -> None:
                    try:
                        await _validate_websocket_url(route.url)
                    except ValueError as exc:
                        try:
                            host = urlsplit(route.url).hostname or "<invalid>"
                        except ValueError:
                            host = "<invalid>"
                        blocked_requests.add(host)
                        logger.warning(
                            "Blocked browser WebSocket to %s: %s",
                            host,
                            exc,
                        )
                        await route.close(code=1008, reason="Destination blocked by policy")
                        return
                    await route.connect_to_server()

                await route_web_socket("**/*", guard_web_socket)

            page = await context.new_page()
            page.set_default_navigation_timeout(settings.page_timeout_ms)
            requests: list[RequestRecord] = []
            page.on("request", lambda request: requests.append(
                RequestRecord(
                    url=request.url,
                    method=request.method,
                    resource_type=request.resource_type,
                    origin=origin_key(request.url),
                    has_body=request.post_data is not None,
                )
            ))

            errors: list[str] = []
            response = None
            try:
                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=settings.page_timeout_ms,
                )
            except PlaywrightTimeoutError as exc:
                errors.append(f"Navigation timed out: {exc}")
                logger.warning("Timed out loading %s for scan %s", url, scan_id)
            except PlaywrightError as exc:
                errors.append(f"Navigation failed: {exc}")
                logger.warning("Failed to load %s for scan %s: %s", url, scan_id, exc)

            try:
                await page.wait_for_load_state(
                    "networkidle",
                    timeout=settings.network_idle_cap_ms,
                )
            except PlaywrightTimeoutError:
                logger.debug("Network did not become idle for %s before the cap", url)
            except PlaywrightError as exc:
                errors.append(f"Page settling failed: {exc}")
                logger.warning("Could not settle page %s for scan %s: %s", url, scan_id, exc)

            page_data: dict = {}
            try:
                page_data = await page.evaluate(_EXTRACT_PAGE_SCRIPT)
            except PlaywrightError as exc:
                errors.append(f"Page capture failed: {exc}")
                logger.warning("Could not capture page %s for scan %s: %s", url, scan_id, exc)

            final_url = page.url if page.url and page.url != "about:blank" else url
            forms = [
                self._form_info(form_data, final_url)
                for form_data in page_data.get("forms", [])
            ]
            images = page_data.get("images", [])
            element_boxes = {
                "forms": [
                    form_data["bounding_box"]
                    for form_data in page_data.get("forms", [])
                    if form_data.get("bounding_box")
                ],
                "password_inputs": page_data.get("password_boxes", []),
                "images": [image["box"] for image in images if image.get("box")],
            }
            logo_candidates = [
                {
                    "path": image["src"],
                    "box": image["box"],
                    "src": image["src"],
                }
                for image in images[:100]
                if image.get("src") and image.get("box")
            ]

            html = page_data.get("html", "")
            html_limit = settings.max_html_bytes
            html = html.encode("utf-8")[:html_limit].decode("utf-8", errors="ignore")
            viewport = page_data.get("viewport") or {
                "width": settings.viewport_width,
                "height": settings.viewport_height,
            }
            text = page_data.get("visible_text", "")
            max_image_coverage = max(
                (
                    (
                        max(
                            0.0,
                            min(
                                image["box"]["x"] + image["box"]["width"],
                                viewport["width"],
                            )
                            - max(image["box"]["x"], 0.0),
                        )
                        * max(
                            0.0,
                            min(
                                image["box"]["y"] + image["box"]["height"],
                                viewport["height"],
                            )
                            - max(image["box"]["y"], 0.0),
                        )
                    )
                    / max(1, viewport["width"] * viewport["height"])
                    for image in images
                    if image.get("box")
                ),
                default=0.0,
            )
            is_image_only = (
                len(text.strip()) < settings.image_only_text_chars
                and max_image_coverage >= settings.image_only_coverage
            )

            screenshot_path: str | None = None
            artifact_dir = settings.artifacts_dir / scan_id
            artifact_dir.mkdir(parents=True, exist_ok=True)
            url_digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
            target_screenshot = artifact_dir / f"page_{url_digest}.png"
            try:
                await page.screenshot(path=str(target_screenshot), full_page=False)
                screenshot_path = str(target_screenshot.resolve())
            except PlaywrightError as exc:
                errors.append(f"Screenshot capture failed: {exc}")
                logger.warning("Could not capture screenshot for scan %s: %s", scan_id, exc)

            if blocked_requests:
                blocked_hosts = ", ".join(sorted(blocked_requests))
                errors.append(f"Blocked private or unvalidated destinations: {blocked_hosts}")

            return PageSnapshot(
                requested_url=url,
                final_url=final_url,
                redirect_chain=self._redirect_chain(response),
                status=response.status if response is not None else None,
                title=page_data.get("title", ""),
                html=html,
                visible_text=text,
                screenshot_path=screenshot_path,
                viewport=viewport,
                forms=forms,
                requests=requests,
                favicon_path=None,
                logo_candidates=logo_candidates,
                element_boxes=element_boxes,
                load_error="; ".join(errors) or None,
                is_image_only=is_image_only,
            )
        finally:
            await context.close()

    @staticmethod
    def _form_info(form_data: dict, page_url: str) -> FormInfo:
        action_raw = form_data.get("action_raw", "")
        action_resolved = resolve_action(action_raw, page_url)
        action_origin = _web_origin(action_resolved)
        page_origin = _web_origin(page_url)
        action_scheme = urlparse(action_resolved).scheme.lower()
        return FormInfo(
            action_raw=action_raw,
            action_resolved=action_resolved,
            action_origin=action_origin,
            method=form_data.get("method", "get").lower(),
            has_password=form_data.get("has_password", False),
            hidden_fields=form_data.get("hidden_fields", []),
            field_names=form_data.get("field_names", []),
            bounding_box=form_data.get("bounding_box"),
            is_cross_origin=bool(action_origin and action_origin != page_origin),
            is_http=action_scheme == "http",
        )

    @staticmethod
    def _redirect_chain(response: Response | None) -> list[str]:
        if response is None:
            return []
        request = response.request
        chain: list[str] = []
        while request.redirected_from is not None:
            request = request.redirected_from
            chain.append(request.url)
        chain.reverse()
        return chain


# Module-level singleton used by the orchestrator
fetcher = PageFetcher()


class _WebSocketRoute(Protocol):
    url: str

    async def close(self, *, code: int | None = None, reason: str | None = None) -> None:
        ...

    async def connect_to_server(self) -> object:
        ...


def _web_origin(url: str) -> str:
    """Serialize an HTTP(S) origin, retaining scheme and non-default port."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        if scheme not in {"http", "https"} or not hostname:
            return ""
        hostname = hostname.lower()
        if ":" in hostname:
            hostname = f"[{hostname}]"
        port = parsed.port
        default_port = 80 if scheme == "http" else 443
        port_part = f":{port}" if port is not None and port != default_port else ""
        return f"{scheme}://{hostname}{port_part}"
    except ValueError:
        return ""


async def _validate_public_url(url: str) -> None:
    """Reject destinations that are not unambiguously public HTTP(S) hosts."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except (ValueError, TypeError) as exc:
        raise ValueError("Destination URL could not be parsed safely.") from exc

    if scheme not in {"http", "https"} or not hostname:
        raise ValueError("Destination is not a valid HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing user information are not allowed.")

    normalized_host = hostname.rstrip(".").lower()
    if (
        normalized_host == "localhost"
        or "." not in normalized_host
        or normalized_host.endswith(_INTERNAL_HOST_SUFFIXES)
    ):
        raise ValueError("Private or internal hostnames are not allowed.")

    port = port if port is not None else (443 if scheme == "https" else 80)
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        try:
            resolved_addresses = await _resolve_host_addresses(normalized_host, port)
        except Exception as exc:
            raise ValueError("Destination hostname could not be validated.") from exc
    else:
        resolved_addresses = [str(address)]

    if not resolved_addresses:
        raise ValueError("Destination hostname resolved to no addresses.")

    try:
        parsed_addresses = [
            ipaddress.ip_address(address.split("%", 1)[0])
            for address in resolved_addresses
        ]
    except (ValueError, TypeError, IndexError) as exc:
        raise ValueError("Destination address could not be validated safely.") from exc
    if any(
        not (
            address.ipv4_mapped.is_global
            if isinstance(address, ipaddress.IPv6Address)
            and address.ipv4_mapped is not None
            else address.is_global
        )
        for address in parsed_addresses
    ):
        raise ValueError("Private or non-public destination addresses are not allowed.")


async def _validate_websocket_url(url: str) -> None:
    """Apply the same public-host rules to browser WebSocket destinations."""
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ValueError("WebSocket destination could not be parsed safely.") from exc
    scheme = {"ws": "http", "wss": "https"}.get(parsed.scheme.lower())
    if scheme is None:
        raise ValueError("Only ws and wss destinations are allowed.")
    http_url = urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment))
    await _validate_public_url(http_url)


async def _resolve_host_addresses(hostname: str, port: int) -> list[str]:
    """Resolve a hostname asynchronously for fail-closed destination checks."""
    loop = asyncio.get_running_loop()
    addresses = await asyncio.wait_for(
        loop.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        ),
        timeout=max(0.1, settings.page_timeout_ms / 1000),
    )
    return [entry[4][0] for entry in addresses]
