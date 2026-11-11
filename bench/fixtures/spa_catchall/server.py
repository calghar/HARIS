import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Same shell and status for every path and method: the false-positive trap.
APP_SHELL = (
    b"<!doctype html><html><head><title>Bench SPA</title></head>"
    b'<body><div id="root"></div><script src="/static/app.js"></script></body></html>'
)


class Handler(BaseHTTPRequestHandler):
    def _respond(self, send_body: bool = True) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(APP_SHELL)))
        self.end_headers()
        if send_body:
            self.wfile.write(APP_SHELL)

    def do_GET(self) -> None:
        self._respond()

    def do_HEAD(self) -> None:
        self._respond(send_body=False)

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._respond()

    do_PUT = do_DELETE = do_PATCH = do_POST  # noqa: N815 - http.server dispatch names

    def log_message(self, format: str, *args: object) -> None:
        pass


def make_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    make_server(args.host, args.port).serve_forever()
