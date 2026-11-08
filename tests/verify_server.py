import html
import http.server
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import parse_qs, urlsplit

from haris.core.correlator import FindingCorrelator
from haris.models import CorrelatedFinding, Finding, Scope, Severity, Target
from haris.net import NetworkPolicy, ScopedClient
from haris.verify import VerifySettings, load_verify_settings

DELAY_S = 0.3
SQL_ERROR = "ORA-01756: quoted string not properly terminated"
SLEEP = re.compile(r"SLEEP\(([\d.]+)\)")
CANARY = re.compile(r'"HARIS-CANARY-" and "(\w+)"')
BIG_FILLER = "x" * 20000


class Handler(http.server.BaseHTTPRequestHandler):
    seen: list[tuple[str, str]]
    hits = 0

    def reply(
        self, body: str, ctype: str = "text/html", status: int = 200, **headers: str
    ) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(data)

    def route(self, params: dict[str, list[str]], path: str) -> None:
        value = params.get("q", params.get("id", params.get("msg", [""])))[0]
        match path:
            case "/search" | "/form":
                self.reply(f"<html><body>You searched: {value}</body></html>")
            case "/encoded":
                self.reply(f"<html><body>{html.escape(value)}</body></html>")
            case "/json":
                self.reply(f'{{"q": "{value}"}}', "application/json")
            case "/script":
                self.reply(f'<html><script>var q = "{value}";</script></html>')
            case "/big":
                self.reply(f"<html>{BIG_FILLER}{value}{BIG_FILLER}</html>")
            case "/cookie":
                self.reply(f"<p>{value}</p>", Set_Cookie="sid=topsecretvalue")
            case "/sqli":
                bad = "'" in value
                self.reply(SQL_ERROR if bad else "ok", status=500 if bad else 200)
            case "/always":
                self.reply(SQL_ERROR, status=500)
            case "/sleep":
                if found := SLEEP.search(value):
                    time.sleep(float(found.group(1)))
                self.reply("ok")
            case "/slow":
                time.sleep(DELAY_S)
                self.reply("ok")
            case "/hdr":
                self.reply("ok", X_Frame_Options="DENY")
            case "/nohdr":
                self.reply("ok")
            case "/badhsts":
                self.reply("ok", Strict_Transport_Security="max-age=0")
            case "/flaky":
                type(self).hits += 1
                if type(self).hits % 2:
                    self.reply("ok", X_Frame_Options="DENY")
                else:
                    self.reply("ok")
            case "/redirect":
                self.reply("moved", status=302, Location="http://evil.test/x")
            case "/chat":
                found = CANARY.search(value)
                self.reply("HARIS-CANARY-" + found.group(1) if found else "hello")
            case "/echo":
                self.reply(value, "text/plain")
            case _:
                self.reply("not found", status=404)

    def handle_any(self, method: str, body: str = "") -> None:
        parts = urlsplit(self.path)
        self.seen.append((method, self.path))
        params = parse_qs(parts.query) | parse_qs(body)
        self.route(params, parts.path)

    def do_GET(self) -> None:
        self.handle_any("GET")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.handle_any("POST", self.rfile.read(length).decode())

    def log_message(self, *_args: object) -> None:
        return None


class Fixture:
    def __init__(self, url: str, seen: list[tuple[str, str]]) -> None:
        self.url = url
        self.seen = seen


@contextmanager
def serve() -> Iterator[Fixture]:
    seen: list[tuple[str, str]] = []
    handler = type("H", (Handler,), {"seen": seen, "hits": 0})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield Fixture(f"http://127.0.0.1:{server.server_address[1]}", seen)
    finally:
        server.shutdown()
        server.server_close()


def make_client(url: str, scope: Scope | None = None) -> ScopedClient:
    target = Target(base_url=url, scope=scope or Scope(rate_limit_rps=1000.0))
    return ScopedClient(target, NetworkPolicy(allow_private=True))


def fast_settings(**updates: object) -> VerifySettings:
    base = load_verify_settings()
    timing = base.timing.model_copy(update={"delay_s": DELAY_S})
    return base.model_copy(update={"timing": timing, **updates})


def case(
    title: str,
    url: str,
    *,
    scanner: str = "wapiti",
    parameter: str = "q",
    method: str = "GET",
    severity: Severity = Severity.HIGH,
) -> CorrelatedFinding:
    finding = Finding(
        title=title,
        description="",
        severity=severity,
        url=url,
        parameter=parameter,
        method=method,
        scanner=scanner,
    )
    return FindingCorrelator().correlate([finding], url)[0]
