from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from app.config import settings
from app.fetcher import PageFetcher


class FakeRequest:
    def __init__(
        self,
        url: str,
        redirected_from: FakeRequest | None = None,
    ) -> None:
        self.url = url
        self.method = "GET"
        self.resource_type = "document"
        self.post_data = None
        self.redirected_from = redirected_from

    def is_navigation_request(self) -> bool:
        return self.resource_type == "document"


class FakeLocator:
    def __init__(self, page: FakePage, selector: str) -> None:
        self.page = page
        self.selector = selector
        self.first = self

    async def inner_text(self, timeout: int = 2000) -> str:
        return ""

    async def evaluate_all(self, _script: str) -> object:
        if self.selector == "form":
            return [
                {
                    "action_raw": "https://collector.test/login",
                    "method": "post",
                    "has_password": True,
                    "hidden_fields": ["csrf"],
                    "field_names": ["email", "password"],
                    "box": {
                        "x": 0,
                        "y": 0,
                        "width": 100,
                        "height": 100,
                    },
                }
            ]
        if self.selector == "img":
            return [
                {
                    "src": "https://suspect.test/logo.png",
                    "alt": "logo",
                    "width": self.page.image_box["width"],
                    "height": self.page.image_box["height"],
                    "x": self.page.image_box["x"],
                    "y": self.page.image_box["y"],
                }
            ]
        if self.selector == "input[type=password]":
            return {
                "password_inputs": {
                    "x": 10,
                    "y": 20,
                    "width": 80,
                    "height": 15,
                }
            }
        return []

    async def get_attribute(self, _name: str, timeout: int = 1000) -> str | None:
        return None


class FakePage:
    def __init__(
        self,
        *,
        navigation_error: Exception | None = None,
        url: str = "https://suspect.test/login",
    ) -> None:
        self.url = url
        self.navigation_error = navigation_error
        self.image_box = {"x": 0, "y": 0, "width": 90, "height": 90}
        self.handlers: dict[str, object] = {}
        self.response = SimpleNamespace(
            status=200,
            url=self.url,
            request=FakeRequest(
                self.url,
                redirected_from=FakeRequest("http://suspect.test/"),
            ),
        )

    def set_default_timeout(self, timeout: int) -> None:
        self.default_timeout = timeout

    def set_default_navigation_timeout(self, timeout: int) -> None:
        self.navigation_timeout = timeout

    async def content(self) -> str:
        return "<html>captured</html>"

    def is_closed(self) -> bool:
        return False

    def on(self, event: str, callback: object) -> None:
        self.handlers[event] = callback

    def locator(self, selector: str) -> FakeLocator:
        return FakeLocator(self, selector)

    async def goto(self, url: str, **_kwargs: object) -> object:
        if self.navigation_error:
            raise self.navigation_error
        self.url = url
        redirected_from = (
            FakeRequest("http://suspect.test/")
            if url == "https://suspect.test/login"
            else None
        )
        request = FakeRequest(url, redirected_from=redirected_from)
        self.response = SimpleNamespace(status=200, url=url, request=request)
        request_callback = self.handlers.get("request")
        if request_callback is not None:
            request_callback(request)
        response_callback = self.handlers.get("response")
        if response_callback is not None:
            response_callback(self.response)
        return self.response

    async def wait_for_load_state(self, _state: str, timeout: int) -> None:
        return None

    async def screenshot(self, path: str, full_page: bool, **_kwargs: object) -> None:
        Path(path).write_bytes(b"png")

    async def title(self) -> str:
        return "Sign in"


class FakeContext:
    def __init__(self, page: FakePage) -> None:
        self.page = page
        self.closed = False
        self.route_handler = None
        self.websocket_handler = None

    async def new_page(self) -> FakePage:
        return self.page

    async def route(self, pattern: str, handler: object) -> None:
        self.route_pattern = pattern
        self.route_handler = handler

    async def route_web_socket(self, pattern: str, handler: object) -> None:
        self.websocket_pattern = pattern
        self.websocket_handler = handler

    async def close(self) -> None:
        self.closed = True



class FakeBrowser:
    def __init__(self, context: FakeContext) -> None:
        self.context = context
        self.viewport: dict[str, int] | None = None
        self.service_workers = "allow"
        self.accept_downloads = False

    async def new_context(
        self,
        *,
        viewport: dict[str, int],
        service_workers: str = "allow",
        accept_downloads: bool = False,
    ) -> FakeContext:
        self.viewport = viewport
        self.service_workers = service_workers
        self.accept_downloads = accept_downloads
        return self.context
@pytest.mark.asyncio
async def test_fetch_builds_snapshot_and_saves_screenshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = FakePage()
    context = FakeContext(page)
    browser = FakeBrowser(context)
    fetcher = PageFetcher()
    fetcher._browser = browser
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)

    snapshot = await fetcher.fetch("https://suspect.test/login", "scan-123")

    assert snapshot.requested_url == "https://suspect.test/login"
    assert snapshot.final_url == page.url
    assert snapshot.redirect_chain == ["http://suspect.test/"]
    assert snapshot.status == 200
    assert snapshot.title == "Sign in"
    assert snapshot.html == "<html>captured</html>"
    assert snapshot.forms[0].has_password
    assert snapshot.forms[0].is_cross_origin
    assert snapshot.forms[0].action_origin == "https://collector.test"
    assert snapshot.forms[0].is_http is False
    assert snapshot.requests[0].origin == "suspect.test"
    assert snapshot.element_boxes["password_inputs"][0].width == 80
    assert snapshot.screenshot_path is not None
    assert Path(snapshot.screenshot_path).parent == (tmp_path / "scan-123").resolve()
    assert Path(snapshot.screenshot_path).name == "page.png"
    assert snapshot.is_image_only
    assert context.closed
    assert browser.viewport == {
        "width": settings.viewport_width,
        "height": settings.viewport_height,
    }
    assert browser.service_workers == "allow"


@pytest.mark.asyncio
async def test_navigation_timeout_returns_partial_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = FakePage(navigation_error=PlaywrightTimeoutError("navigation timeout"))
    context = FakeContext(page)
    fetcher = PageFetcher()
    fetcher._browser = FakeBrowser(context)
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)

    snapshot = await fetcher.fetch("https://suspect.test/login", "scan-timeout")

    assert snapshot.load_error is not None
    assert "Navigation timed out" in snapshot.load_error
    assert snapshot.title == "Sign in"
    assert context.closed


@pytest.mark.asyncio
async def test_offscreen_image_does_not_mark_page_image_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = FakePage()
    page.image_box = {
        "x": 0,
        "y": settings.viewport_height + 120,
        "width": 100,
        "height": 100,
    }
    context = FakeContext(page)
    fetcher = PageFetcher()
    fetcher._browser = FakeBrowser(context)
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)

    snapshot = await fetcher.fetch("https://suspect.test/login", "scan-offscreen")

    assert snapshot.is_image_only is False


@pytest.mark.asyncio
async def test_fetch_rejects_invalid_url_before_opening_context() -> None:
    fetcher = PageFetcher()
    browser = FakeBrowser(FakeContext(FakePage()))
    fetcher._browser = browser

    snapshot = await fetcher.fetch("file:///etc/passwd", "scan-123")

    assert snapshot.load_error is not None
    assert "Invalid or unsupported URL" in snapshot.load_error
    assert browser.viewport is None


@pytest.mark.asyncio
async def test_private_destination_is_rejected_when_private_hosts_are_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = PageFetcher()
    browser = FakeBrowser(FakeContext(FakePage()))
    fetcher._browser = browser
    monkeypatch.setattr(settings, "allow_private_hosts", False)

    snapshot = await fetcher.fetch("http://127.0.0.1/login", "scan-private")

    assert snapshot.load_error is not None
    assert "Private or non-public" in snapshot.load_error
    assert browser.viewport is None


@pytest.mark.asyncio
async def test_internal_hostname_is_rejected_when_private_hosts_are_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = PageFetcher()
    fetcher._browser = FakeBrowser(FakeContext(FakePage()))
    monkeypatch.setattr(settings, "allow_private_hosts", False)

    snapshot = await fetcher.fetch("http://printer.local/login", "scan-internal")

    assert snapshot.load_error is not None
    assert "Internal hostnames" in snapshot.load_error


@pytest.mark.asyncio
async def test_hostname_resolving_to_private_address_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def resolve_to_private_address(hostname: str, port: int) -> list[str]:
        return ["10.20.30.40"]

    fetcher = PageFetcher()
    fetcher._browser = FakeBrowser(FakeContext(FakePage()))
    monkeypatch.setattr(settings, "allow_private_hosts", False)
    monkeypatch.setattr(
        "app.fetcher._resolve_host_addresses",
        resolve_to_private_address,
    )

    snapshot = await fetcher.fetch("https://attacker.com/login", "scan-private-dns")

    assert snapshot.load_error is not None
    assert "Private or non-public" in snapshot.load_error


@pytest.mark.asyncio
async def test_unresolvable_destination_is_rejected_when_private_hosts_are_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_resolution(hostname: str, port: int) -> list[str]:
        raise OSError("DNS lookup failed")

    fetcher = PageFetcher()
    fetcher._browser = FakeBrowser(FakeContext(FakePage()))
    monkeypatch.setattr(settings, "allow_private_hosts", False)
    monkeypatch.setattr("app.fetcher._resolve_host_addresses", fail_resolution)

    snapshot = await fetcher.fetch("https://unknown.com/login", "scan-unknown")

    assert snapshot.load_error is not None
    assert "DNS lookup failed" in snapshot.load_error


@pytest.mark.asyncio
async def test_browser_route_blocks_private_redirects_and_subresources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def allow_only_public_example(url: str) -> None:
        if url != "https://public.example/login":
            raise ValueError("Private or non-public destination addresses are not allowed.")

    context = FakeContext(FakePage())
    browser = FakeBrowser(context)
    fetcher = PageFetcher()
    fetcher._browser = browser
    monkeypatch.setattr(settings, "allow_private_hosts", False)
    monkeypatch.setattr("app.fetcher._validate_public_url", allow_only_public_example)

    await fetcher.fetch("https://public.example/login", "scan-routes")
    assert context.route_pattern == "**/*"
    assert context.route_handler is not None
    assert context.websocket_pattern == "**/*"
    assert context.websocket_handler is not None
    assert browser.service_workers == "block"

    class FakeRoute:
        def __init__(self, url: str) -> None:
            self.request = FakeRequest(url)
            self.aborted_with: str | None = None

        async def abort(self, error_code: str = "blockedbyclient") -> None:
            self.aborted_with = error_code

        async def continue_(self) -> None:
            raise AssertionError("Unsafe request must not be continued.")

    handler = context.route_handler
    redirect = FakeRoute("http://10.0.0.1/admin")
    image = FakeRoute("http://192.168.1.1/metadata")

    await handler(redirect)
    await handler(image)

    assert redirect.aborted_with == "blockedbyclient"
    assert image.aborted_with == "blockedbyclient"

    class FakeWebSocketRoute:
        def __init__(self, url: str) -> None:
            self.url = url
            self.closed_with: tuple[int | None, str | None] | None = None
            self.connected = False

        async def close(self, *, code: int | None = None, reason: str | None = None) -> None:
            self.closed_with = (code, reason)

        async def connect_to_server(self) -> None:
            self.connected = True

    websocket = FakeWebSocketRoute("ws://127.0.0.1/admin")
    websocket_handler = context.websocket_handler
    await websocket_handler(websocket)

    assert websocket.closed_with == (1008, "Blocked unsafe WebSocket destination")
    assert websocket.connected is False


@pytest.mark.asyncio
async def test_fetch_rejects_unsafe_scan_id() -> None:
    fetcher = PageFetcher()
    browser = FakeBrowser(FakeContext(FakePage()))
    fetcher._browser = browser

    with pytest.raises(ValueError, match="scan_id"):
        await fetcher.fetch("https://suspect.test", "..\\outside")

    assert browser.viewport is None


@pytest.mark.asyncio
async def test_fetch_starts_browser_automatically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = PageFetcher()
    context = FakeContext(FakePage())
    browser = FakeBrowser(context)
    calls: list[str] = []

    async def fake_startup() -> None:
        calls.append("startup")
        fetcher._browser = browser

    monkeypatch.setattr(fetcher, "startup", fake_startup)
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)

    snapshot = await fetcher.fetch("https://suspect.test/login", "scan-123")

    assert calls == ["startup"]
    assert snapshot.load_error is None
    assert context.closed


@pytest.mark.asyncio
async def test_startup_and_shutdown_manage_browser_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    browser = SimpleNamespace(
        close=_async_call(calls, "browser.close"),
    )
    playwright = SimpleNamespace(
        chromium=SimpleNamespace(launch=_async_return(browser)),
        stop=_async_call(calls, "playwright.stop"),
    )
    monkeypatch.setattr(
        "app.fetcher.async_playwright",
        lambda: SimpleNamespace(start=_async_return(playwright)),
    )
    fetcher = PageFetcher()

    await fetcher.startup()
    await fetcher.shutdown()

    assert calls == ["browser.close", "playwright.stop"]
    assert fetcher._browser is None
    assert fetcher._playwright is None


def _async_call(calls: list[str], name: str):
    async def call() -> None:
        calls.append(name)

    return call


def test_form_origin_includes_scheme_and_effective_port() -> None:
    form_data = {
        "action_raw": "http://login.example.test:80/submit",
        "method": "post",
    }

    form = PageFetcher._form_info(form_data, "https://login.example.test/login")

    assert form.action_origin == "http://login.example.test"
    assert form.is_cross_origin


def test_form_origin_distinguishes_non_default_ports() -> None:
    form_data = {
        "action_raw": "https://login.example.test:8443/submit",
        "method": "post",
    }

    form = PageFetcher._form_info(form_data, "https://login.example.test/login")

    assert form.action_origin == "https://login.example.test:8443"
    assert form.is_cross_origin


def test_form_origin_treats_default_port_as_same_origin() -> None:
    form_data = {
        "action_raw": "https://login.example.test:443/submit",
        "method": "post",
    }

    form = PageFetcher._form_info(form_data, "https://login.example.test/login")

    assert form.action_origin == "https://login.example.test"
    assert form.is_cross_origin is False


def _async_return(value: object):
    async def call(**_kwargs: object) -> object:
        return value

    return call
