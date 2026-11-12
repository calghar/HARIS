import http.server
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from haris.core.vuln_class import get_registry
from haris.models import VerificationMethod, VerificationOracle, VerificationTier
from haris.verify import oracles
from haris.verify.oracles import ORACLES
from haris.verify.replay import replay
from haris.verify.settings import load_verify_settings
from haris.verify.timing import timing_positive
from tests.verify_server import Fixture, Handler, case, fast_settings, make_client

T = VerificationTier
PASSWD = "root:x:0:0:root:/root:/bin/bash"
MARKER_HEX = "0123456789abcdef"
MARKER_URL = f"http://haris-{MARKER_HEX}.invalid/"
SLEEP = re.compile(r"sleep ([\d.]+)")


class WapitiHandler(Handler):
    def route(self, params: dict[str, list[str]], path: str) -> None:
        value = params.get("q", [""])[0]
        match path:
            case "/lfi":
                self.reply(PASSWD if "passwd" in value else "ok", "text/plain")
            case "/lfi-always":
                self.reply(PASSWD, "text/plain")
            case "/redir":
                if value.startswith("http://"):
                    self.reply("moved", status=302, Location=MARKER_URL)
                else:
                    self.reply("ok")
            case "/login-redir":
                self.reply("moved", status=302, Location="/login")
            case "/cmd":
                if found := SLEEP.search(value):
                    time.sleep(float(found.group(1)))
                self.reply("ok")
            case _:
                super().route(params, path)


@contextmanager
def serve_wapiti() -> Iterator[Fixture]:
    seen: list[tuple[str, str]] = []
    handler = type("H", (WapitiHandler,), {"seen": seen, "hits": 0})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield Fixture(f"http://127.0.0.1:{server.server_address[1]}", seen)
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    ("title", "path", "tier", "oracle"),
    [
        (
            "Path Traversal",
            "/lfi",
            T.REPLAY_VERIFIED,
            VerificationOracle.PATH_TRAVERSAL,
        ),
        (
            "Path Traversal",
            "/lfi-always",
            T.UNVERIFIED,
            VerificationOracle.PATH_TRAVERSAL,
        ),
        (
            "Open Redirect",
            "/redir",
            T.REPLAY_VERIFIED,
            VerificationOracle.OPEN_REDIRECT,
        ),
        (
            "Open Redirect",
            "/login-redir",
            T.UNVERIFIED,
            VerificationOracle.OPEN_REDIRECT,
        ),
        ("Command execution", "/cmd", T.REPLAY_VERIFIED, VerificationOracle.TIMING_CMD),
        ("Command execution", "/slow", T.UNVERIFIED, VerificationOracle.TIMING_CMD),
    ],
    ids=[
        "path-traversal-probe-only",
        "path-traversal-probe-and-control",
        "open-redirect-to-marker-host",
        "open-redirect-login-page-in-both",
        "command-injection-sleeps-on-payload",
        "command-injection-slow-but-constant",
    ],
)
def test_oracle_matrix_for_wapiti_classes(
    monkeypatch: pytest.MonkeyPatch,
    title: str,
    path: str,
    tier: VerificationTier,
    oracle: VerificationOracle,
) -> None:
    """Scenario: Oracle matrix for new classes."""
    monkeypatch.setattr(
        oracles, "secrets", SimpleNamespace(token_hex=lambda _n: MARKER_HEX)
    )
    with serve_wapiti() as fx:
        finding = case(title, f"{fx.url}{path}?q=1")
        with make_client(fx.url) as client:
            replay([finding], client, fast_settings())
    verification = finding.canonical.verification
    assert verification.tier == tier
    assert verification.method == VerificationMethod.REPLAY
    assert verification.oracle == oracle


@pytest.mark.parametrize(
    ("probe", "control", "expected"),
    [
        ([5.3, 5.3, 5.3], [0.2, 0.2, 0.2], True),
        ([0.3, 0.3, 0.3], [0.2, 0.2, 0.2], False),
    ],
    ids=["probe-5.3s-control-0.2s", "probe-0.3s-control-0.2s"],
)
def test_command_injection_timing_decision_with_five_second_delay(
    probe: list[float], control: list[float], expected: bool
) -> None:
    assert timing_positive(probe, control, 5.0, 0.8) is expected


@pytest.mark.parametrize(
    "title", ["Server Side Request Forgery", "XML External Entity"]
)
def test_ssrf_and_xxe_stay_unverified_with_method_none(title: str) -> None:
    with serve_wapiti() as fx:
        finding = case(title, f"{fx.url}/lfi?q=1")
        with make_client(fx.url) as client:
            report = replay([finding], client, fast_settings())
    verification = finding.canonical.verification
    assert (verification.tier, verification.method) == (
        T.UNVERIFIED,
        VerificationMethod.NONE,
    )
    assert fx.seen == []
    assert report.requests == 0


def test_vuln_classes_yaml_names_oracles_for_new_classes_only() -> None:
    classes = get_registry().classes
    assert {
        c: classes[c].oracle
        for c in ("path_traversal", "open_redirect", "command_injection")
    } == {
        "path_traversal": "path_traversal",
        "open_redirect": "open_redirect",
        "command_injection": "timing_cmd",
    }
    assert {classes[c].oracle for c in ("ssrf", "xxe")} == {"none"}
    assert {"path_traversal", "open_redirect", "timing_cmd"} <= set(ORACLES)


def test_command_payloads_only_sleep() -> None:
    payloads = load_verify_settings().timing.cmd_payloads
    assert payloads
    assert all(re.fullmatch(r"[;|$(`\s]*sleep \{d\}[)`]*", p) for p in payloads), (
        payloads
    )
