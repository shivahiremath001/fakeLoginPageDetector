
import pytest

from app.fetcher import PageFetcher, UnsafeTargetError, _validate_target



@pytest.mark.asyncio
async def test_invalid_url_returns_error_without_starting_browser():
    fetcher = PageFetcher()

    result = await fetcher.fetch("javascript:alert(1)", "test-invalid")

    assert result.load_error == "Invalid or unsupported URL."
    assert result.html == ""
    assert result.screenshot_path is None



@pytest.mark.asyncio
async def test_local_page_capture(tmp_path, monkeypatch):
    from app.config import settings

    # Keep generated screenshots inside pytest's temporary directory.
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)
    monkeypatch.setattr(settings, "allow_private_hosts", True)

    fetcher = PageFetcher()
    await fetcher.startup()

    try:
        context = await fetcher._browser.new_context()
        page = await context.new_page()

        await page.set_content("""
            <!doctype html>
            <html>
              <head><title>Test Login Page</title></head>
              <body>
                <h1>Welcome</h1>
                <form action="/login" method="post">
                  <input name="username">
                  <input type="password" name="password">
                  <button type="submit">Sign in</button>
                </form>
              </body>
            </html>
        """)

        # Use a temporary local HTTP server in the next test for a full
        # fetch() integration test. This test validates browser availability.
        assert await page.title() == "Test Login Page"
        assert await page.locator("form").count() == 1

        await context.close()
    finally:
        await fetcher.shutdown()


@pytest.mark.asyncio
async def test_private_target_allowed_for_local_hackathon(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "allow_private_hosts", True)

    # Local targets are required for the hackathon's test pages.
    await _validate_target("http://127.0.0.1:5001/")


@pytest.mark.asyncio
async def test_private_target_rejected_when_private_hosts_disabled(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "allow_private_hosts", False)

    with pytest.raises(UnsafeTargetError):
        await _validate_target("http://127.0.0.1:5001/")


import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


@pytest.mark.asyncio
async def test_fetch_captures_local_page(tmp_path, monkeypatch):
    from app.config import settings

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"""
            <!doctype html>
            <html>
              <head><title>Local Test Login</title></head>
              <body>
                <h1>Welcome</h1>
                <form action="/login" method="post">
                  <input name="username">
                  <input type="password" name="password">
                  <button type="submit">Sign in</button>
                </form>
              </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)
    monkeypatch.setattr(settings, "allow_private_hosts", True)

    fetcher = PageFetcher()

    try:
        result = await fetcher.fetch(
            f"http://127.0.0.1:{server.server_port}/",
            "integration-test",
        )

        assert result.load_error is None
        assert result.title == "Local Test Login"
        assert "Welcome" in result.visible_text
        assert len(result.forms) == 1
        assert result.forms[0].has_password is True
        assert result.screenshot_path is not None
        assert __import__("pathlib").Path(result.screenshot_path).exists()
    finally:
        await fetcher.shutdown()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

