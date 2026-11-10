import argparse
import json
import re
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from typing import Any
from urllib.parse import parse_qs, urlsplit

# Wapiti 3.3.2 target side: /ssrf/<session>/<path_id>/<hex_param>/ and
# /dtd/<session>/<path_id>/<hex_param>/<payload>.dtd; read side: /get_<ssrf|xxe>.php.
CALLBACK = re.compile(
    r"^/(?P<kind>ssrf|dtd)/(?P<session>[0-9a-z]+)/(?P<path_id>\d+)"
    r"/(?P<param>[0-9a-f]+)/(?P<name>[\w.-]*)$"
)
READ = re.compile(r"^/get_(?P<kind>ssrf|xxe)\.php$")
KIND_OF_READ = {"ssrf": "ssrf", "xxe": "dtd"}
DTD_SUFFIX = ".dtd"
SESSION_QUERY = "session_id"
JSON_TYPE = "application/json"
# kind -> session -> path_id -> hex_param -> [record]
Store = dict[str, dict[str, dict[str, dict[str, list[dict[str, Any]]]]]]


class Receiver(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, Handler)
        self.store: Store = {}
        self.lock = Lock()


class Handler(BaseHTTPRequestHandler):
    server: Receiver

    def _send(self, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _record(self, match: re.Match[str], size: int) -> None:
        kind = match["kind"]
        record: dict[str, Any] = {
            "url": self.path,
            "date": datetime.now(UTC).isoformat(),
            "ip": self.client_address[0],
            "method": self.command,
            "size": size,
        }
        if kind == "dtd":
            record["payload"] = match["name"].removesuffix(DTD_SUFFIX)
        with self.server.lock:
            by_session = self.server.store.setdefault(kind, {})
            by_path = by_session.setdefault(match["session"], {})
            by_param = by_path.setdefault(match["path_id"], {})
            by_param.setdefault(match["param"], []).append(record)

    def _read(self, kind: str, query: str) -> None:
        session = parse_qs(query).get(SESSION_QUERY, [""])[0]
        with self.server.lock:
            found = self.server.store.get(KIND_OF_READ[kind], {}).get(session, {})
            body = json.dumps(found).encode()
        self._send(body, JSON_TYPE)

    def _dispatch(self) -> None:
        size = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(size)
        parts = urlsplit(self.path)
        read = READ.match(parts.path)
        if self.command == "GET" and read:
            self._read(read["kind"], parts.query)
            return
        callback = CALLBACK.match(parts.path)
        if callback:
            self._record(callback, size)
        is_dtd = callback is not None and callback["kind"] == "dtd"
        self._send(b"" if is_dtd else b"ok")

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = _dispatch  # noqa: N815

    def log_message(self, format: str, *args: object) -> None:
        pass


def make_server(host: str = "127.0.0.1", port: int = 0) -> Receiver:
    return Receiver((host, port))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9090)
    args = parser.parse_args()
    make_server(args.host, args.port).serve_forever()
