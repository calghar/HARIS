import argparse
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PASSWD = "root:x:0:0:root:/root:/bin/bash\n"
SQL_ERROR = "You have an error in your SQL syntax; check the manual near '''"


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.2.8"
    sys_version = "(Ubuntu) DAV/2"

    def _send(
        self,
        body: str,
        status: int = 200,
        headers: dict[str, str] | None = None,
        content_type: str = "text/html",
    ) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Powered-By", "PHP/5.2.4")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/":
            self._send(
                "<html><head><title>Fixture</title></head><body>"
                '<a href="/search?q=a">search</a> <a href="/item?id=1">item</a> '
                '<a href="/file?name=a.txt">file</a> <a href="/go?url=/">go</a> '
                '<a href="/admin/">admin</a>'
                '<form action="/search" method="get"><input name="q"></form>'
                "</body></html>",
                headers={"Set-Cookie": "sid=abc123; Path=/"},
            )
        elif url.path == "/search":
            self._send(f"<html><body>Results for {query.get('q', '')}</body></html>")
        elif url.path == "/item":
            item = query.get("id", "")
            body = SQL_ERROR if "'" in item else f"item {item}"
            self._send(f"<html><body>{body}</body></html>")
        elif url.path == "/file":
            name = query.get("name", "")
            body = PASSWD if "../" in name or "etc/passwd" in name else "file"
            self._send(body, content_type="text/plain")
        elif url.path == "/go":
            self._send("", 302, {"Location": query.get("url", "/")})
        elif url.path == "/admin/":
            self._send(
                "<html><title>Index of /admin</title><h1>Index of /admin</h1></html>"
            )
        elif url.path == "/phpinfo.php":
            self._send("<html><title>phpinfo()</title>PHP Version 5.2.4</html>")
        else:
            self._send("<html>not found</html>", 404)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send("", 200, {"Allow": "GET, HEAD, POST, OPTIONS, TRACE"})

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument(
        "--min-tls", help="ssl.TLSVersion member, e.g. TLSv1 for legacy captures"
    )
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    if args.cert and args.key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if args.min_tls:
            context.minimum_version = getattr(ssl.TLSVersion, args.min_tls)
            context.set_ciphers("ALL:@SECLEVEL=0")
        context.load_cert_chain(args.cert, args.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
