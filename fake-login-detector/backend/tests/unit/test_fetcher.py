
import pytest
import asyncio
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

    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)
    monkeypatch.setattr(settings, "allow_private_hosts", True)

    fetcher = PageFetcher()
    await fetcher.startup()

    async def on_worker(coro):
        """Run Playwright operations on the browser's owning event loop."""
        assert fetcher._worker_loop is not None
        future = asyncio.run_coroutine_threadsafe(
            coro, fetcher._worker_loop
        )
        return await asyncio.wrap_future(future)

    try:
        context = await on_worker(fetcher._browser.new_context())
        try:
            page = await on_worker(context.new_page())

            await on_worker(page.set_content("""
                <!doctype html>
                <html>
                  <head><title>Test Login Page</title></head>
                  <body>
                    <h1>Welcome</h1>
                    <img
                        src="/logo.svg"
                        alt="Test Company Logo"
                        width="120"
                        height="60"
                    />
                    <form action="/login" method="post">
                      <input name="username">
                      <input type="password" name="password">
                      <button type="submit">Sign in</button>
                    </form>
                  </body>
                </html>
            """))

            title = await on_worker(page.title())
            form_count = await on_worker(
                page.locator("form").count()
            )

            assert title == "Test Login Page"
            assert form_count == 1
        finally:
            await on_worker(context.close())
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
            if self.path == "/logo.svg":
                body = b"""
                <svg xmlns="http://www.w3.org/2000/svg"
                     width="120" height="60">
                  <rect width="120" height="60" fill="blue"/>
                  <text x="10" y="35" fill="white">TEST LOGO</text>
                </svg>
                """
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = b"""
            <!doctype html>
            <html>
              <head><title>Local Test Login</title></head>
              <body>
              <h1>Welcome</h1>
              <img
                src="/logo.svg"
                alt="Test Company Logo"
                width="120"
                height="60"
                />
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
        assert any(
            candidate.get("alt") == "Test Company Logo"
            for candidate in result.logo_candidates
        )
    finally:
        await fetcher.shutdown()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

