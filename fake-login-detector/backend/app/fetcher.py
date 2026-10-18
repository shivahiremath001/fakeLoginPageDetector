
"""Playwright page capture for the Fake Login Page Detector."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from pathlib import Path
from urllib.parse import urljoin, urlparse

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

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_IGNORED_RESOURCE_TYPES = {"image", "media", "font"}
_MAX_REQUESTS = 500


class UnsafeTargetError(ValueError):
    """Raised when a URL resolves to a disallowed network target."""


async def _validate_target(url: str) -> None:
    """Validate URL scheme and destination before navigation."""
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise UnsafeTargetError("Only HTTP and HTTPS URLs are allowed.")

    host = parsed.hostname
    if not host:
        raise UnsafeTargetError("The URL has no hostname.")

    if settings.allow_private_hosts:
        return

    try:
        addresses = await asyncio.get_running_loop().getaddrinfo(
            host, parsed.port or (443 if parsed.scheme == "https" else 80)
        )
    except OSError as exc:
        raise UnsafeTargetError("The hostname could not be resolved.") from exc

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise UnsafeTargetError(
                "Private, local, or non-public network destinations are blocked."
            )


class PageFetcher:
    """Manage a shared Chromium browser and capture pages safely."""

    def __init__(self) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._lock = asyncio.Lock()

    async def startup(self) -> None:
        """Start Chromium once for the application."""
        async with self._lock:
            if self._browser is not None and self._browser.is_connected():
                return

            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True
            )
            logger.info("Playwright Chromium started.")

    async def shutdown(self) -> None:
        """Close the shared browser and Playwright runtime."""
        async with self._lock:
            if self._browser is not None:
                await self._browser.close()
                self._browser = None

            if self._playwright is not None:
                await self._playwright.stop()
                self._playwright = None

            logger.info("Playwright Chromium stopped.")

    async def fetch(self, url: str, scan_id: str) -> PageSnapshot:
        """Render a page and collect its HTML, screenshot, forms, and requests."""
        normalized = normalize_url(url)
        if not normalized:
            return PageSnapshot(
                requested_url=url,
                load_error="Invalid or unsupported URL.",
            )

        try:
            await _validate_target(normalized)
        except (UnsafeTargetError, ValueError) as exc:
            return PageSnapshot(
                requested_url=normalized,
                final_url=normalized,
                load_error=str(exc),
            )

        if self._browser is None or not self._browser.is_connected():
            try:
                await self.startup()
            except Exception as exc:
                logger.exception("Could not start Chromium.")
                return PageSnapshot(
                    requested_url=normalized,
                    final_url=normalized,
                    load_error=f"Browser startup failed: {type(exc).__name__}.",
                )

        assert self._browser is not None

        context: BrowserContext | None = None
        page: Page | None = None
        redirect_chain: list[str] = []
        requests: list[RequestRecord] = []
        request_urls: set[str] = set()
        response_status: int | None = None

        try:
            context = await self._browser.new_context(
                viewport={
                    "width": settings.viewport_width,
                    "height": settings.viewport_height,
                },
                accept_downloads=False,
            )
            page = await context.new_page()
            page.set_default_navigation_timeout(settings.page_timeout_ms)
            page.set_default_timeout(settings.page_timeout_ms)

            # Abort downloads and avoid loading large nonessential media.
            async def route_request(route) -> None:
                request = route.request
                if request.resource_type in _IGNORED_RESOURCE_TYPES:
                    await route.abort()
                    return
                await route.continue_()

            await page.route("**/*", route_request)

            # Validate each destination before the browser follows a request.
            async def validate_navigation(route) -> None:
                target = route.request.url
                if route.request.is_navigation_request():
                    try:
                        await _validate_target(target)
                    except (UnsafeTargetError, ValueError):
                        await route.abort()
                        return
                await route.continue_()

            await page.unroute("**/*", route_request)
            await page.route("**/*", validate_navigation)

            def record_request(request) -> None:
                if len(requests) >= _MAX_REQUESTS:
                    return
                if request.url in request_urls:
                    return
                request_urls.add(request.url)
                try:
                    requests.append(
                        RequestRecord(
                            url=request.url,
                            method=request.method,
                            resource_type=request.resource_type,
                            origin=urlparse(request.url).netloc.lower(),
                            has_body=request.post_data is not None,
                        )
                    )
                except Exception:
                    logger.debug("Skipping malformed network request.")

            page.on("request", record_request)

            def record_response(response) -> None:
                nonlocal response_status
                if response.request.is_navigation_request():
                    response_status = response.status
                    response_url = response.url
                    if response_url != normalized and response_url not in redirect_chain:
                        redirect_chain.append(response_url)

            page.on("response", record_response)

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

            final_url = page.url or normalized
            await _validate_target(final_url)

            html = await page.content()
            if len(html.encode("utf-8", errors="replace")) > settings.max_html_bytes:
                html = html.encode("utf-8", errors="replace")[
                    :settings.max_html_bytes
                ].decode("utf-8", errors="ignore")

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

            forms: list[FormInfo] = []
            form_data = await page.locator("form").evaluate_all(
                """forms => forms.map(form => {
                    const rect = form.getBoundingClientRect();
                    const fields = Array.from(
                        form.querySelectorAll('input, select, textarea')
                    );
                    return {
                        action: form.getAttribute('action') || '',
                        method: (form.getAttribute('method') || 'get').toLowerCase(),
                        has_password: fields.some(
                            field => field.type.toLowerCase() === 'password'
                        ),
                        hidden_fields: fields
                            .filter(field => field.type.toLowerCase() === 'hidden')
                            .map(field => field.name)
                            .filter(Boolean),
                        field_names: fields
                            .filter(field => field.type.toLowerCase() !== 'hidden')
                            .map(field => field.name)
                            .filter(Boolean),
                        box: {
                            x: rect.x, y: rect.y,
                            width: rect.width, height: rect.height
                        }
                    };
                })"""
            )

            for item in form_data:
                action = resolve_action(item["action"], final_url)
                page_origin = urlparse(final_url)
                action_origin = urlparse(action)
                same_origin = (
                    page_origin.scheme == action_origin.scheme
                    and page_origin.hostname == action_origin.hostname
                    and page_origin.port == action_origin.port
                )
                forms.append(
                    FormInfo(
                        action_raw=item["action"],
                        action_resolved=action,
                        action_origin=action_origin.netloc.lower(),
                        method=item["method"],
                        has_password=item["has_password"],
                        hidden_fields=item["hidden_fields"],
                        field_names=item["field_names"],
                        bounding_box=BoundingBox(**item["box"]),
                        is_cross_origin=not same_origin,
                        is_http=action_origin.scheme == "http",
                    )
                )

            favicon_path = None
            try:
                favicon_href = await page.locator(
                    'link[rel~="icon"]'
                ).first.get_attribute("href", timeout=1000)
                if favicon_href:
                    favicon_url = urljoin(final_url, favicon_href)
                    if urlparse(favicon_url).scheme in {"http", "https"}:
                        favicon_response = await context.request.get(
                            favicon_url,
                            timeout=2000,
                        )
                        if favicon_response.ok:
                            content_type = favicon_response.headers.get(
                                "content-type", ""
                            )
                            if content_type.startswith("image/"):
                                suffix = Path(urlparse(favicon_url).path).suffix
                                if suffix.lower() not in {
                                    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp"
                                }:
                                    suffix = ".ico"
                                favicon_file = artifact_dir / f"favicon{suffix}"
                                favicon_file.write_bytes(
                                    await favicon_response.body()
                                )
                                favicon_path = str(favicon_file)
                        await favicon_response.dispose()
            except Exception:
                logger.debug("Favicon capture failed.", exc_info=True)

            logo_candidates: list[dict] = []
            try:
                candidates = await page.locator("img").evaluate_all(
                    """images => images.slice(0, 30).map(img => {
                        const r = img.getBoundingClientRect();
                        return {
                            src: img.currentSrc || img.src || '',
                            alt: img.alt || '',
                            width: r.width,
                            height: r.height,
                            x: r.x,
                            y: r.y
                        };
                    })"""
                )
                for candidate in candidates:
                    if not candidate["src"]:
                        continue
                    if candidate["width"] < 24 or candidate["height"] < 16:
                        continue
                    logo_candidates.append({
                        "src": candidate["src"],
                        "alt": candidate["alt"],
                        "box": {
                            "x": candidate["x"],
                            "y": candidate["y"],
                            "width": candidate["width"],
                            "height": candidate["height"],
                        },
                    })
            except PlaywrightError:
                pass

            is_image_only = (
                len(visible_text.strip()) < settings.image_only_text_chars
                and bool(logo_candidates)
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
                is_image_only=is_image_only,
            )

        except Exception as exc:
            logger.exception("Page capture failed for %s", normalized)
            return PageSnapshot(
                requested_url=normalized,
                final_url=page.url if page and not page.is_closed() else normalized,
                redirect_chain=redirect_chain,
                status=response_status,
                load_error=f"Page capture failed: {type(exc).__name__}.",
                requests=requests,
            )
        finally:
            if context is not None:
                await context.close()


fetcher = PageFetcher()
