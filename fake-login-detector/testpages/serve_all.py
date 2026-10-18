
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlparse

PAGES = {
    5001: {
        "title": "Greenfield College Portal",
        "heading": "Greenfield College",
        "subtitle": "Student Portal",
        "button": "Sign in",
        "action": "/login",
        "color": "#174a82",
    },
    5002: {
        "title": "Greenfield College Portal",
        "heading": "Greenfield College",
        "subtitle": "Student Portal",
        "button": "Sign in",
        "action": "http://localhost:5006/submit",
        "color": "#174a82",
    },
    5006: {
        "title": "Greenfield Webmail",
        "heading": "Greenfield",
        "subtitle": "Webmail",
        "button": "Open Mail",
        "action": "/login",
        "color": "#174a82",
    },
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        page = PAGES[self.server.server_port]

        if urlparse(self.path).path not in ("/", "/login"):
            self.send_error(404)
            return

        html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{page['title']}</title>
<style>
* {{ box-sizing: border-box; }}
body {{
  margin: 0; background: #f1f5f9; color: #243247;
  font: 16px Arial, sans-serif;
}}
header {{
  background: {page['color']}; color: white;
  padding: 22px; text-align: center;
}}
main {{
  width: min(400px, calc(100% - 32px));
  margin: 55px auto; padding: 30px;
  background: white; border-radius: 10px;
  box-shadow: 0 5px 22px #0001;
}}
h2 {{ margin-top: 0; }}
label {{ display: block; margin: 16px 0 6px; }}
input {{
  width: 100%; padding: 12px; border: 1px solid #cbd5e1;
  border-radius: 5px;
}}
button {{
  width: 100%; margin-top: 22px; padding: 12px;
  border: 0; border-radius: 5px;
  background: {page['color']}; color: white;
  font-weight: bold; cursor: pointer;
}}
.note {{ color: #64748b; font-size: 12px; margin-top: 20px; }}
</style>
</head>
<body>
<header><strong>{page['heading']}</strong></header>
<main>
<h2>{page['subtitle']}</h2>
<p>Sign in to continue to your account.</p>
<form method="post" action="{page['action']}">
<label for="username">Student ID / Email</label>
<input id="username" name="username" autocomplete="off">
<label for="password">Password</label>
<input id="password" name="password" type="password"
       autocomplete="off">
<button type="button"> {page['button']} </button>
</form>
<p class="note">DEMO ONLY — do not enter real credentials.</p>
</main>
</body>
</html>"""

        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # Never accept or store submitted form data.
        self.send_error(405, "Demo server does not accept form submissions")

    def log_message(self, fmt, *args):
        print(f"[{self.server.server_port}] {fmt % args}")


def main():
    servers = []

    for port in PAGES:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        print(f"Demo page running: http://localhost:{port}/login")

    print("\nPress Ctrl+C to stop all demo servers.")

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping demo servers...")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
