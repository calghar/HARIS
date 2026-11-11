import http.server
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from haris.core.correlator import FindingCorrelator
from haris.core.vuln_class import get_registry
from haris.models import (
    CorrelatedFinding,
    Finding,
    Severity,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
)
from haris.verify import load_verify_settings
from haris.verify.oracles import ORACLES
from haris.verify.probe import Prober
from haris.verify.replay import replay
from tests.verify_server import case, fast_settings, make_client, serve

T = VerificationTier
CATCH_ALL_PAGE = "<html><head><title>Welcome</title></head><body>Hello</body></html>"
ENV_BODY = "APP_ENV=prod\nDB_PASSWORD=hunter2\n"
LOGIN_PAGE = "<html><title>Login</title><body>sign in</body></html>"


def sensitive(url: str, path: str):
    return case(
        f"Accessible sensitive path: {path}",
        f"{url}{path}",
        scanner="misc_checks",
        parameter="",
    )


@contextmanager
def host(*, catch_all: bool, files: dict[str, tuple[str, str]]) -> Iterator[str]:
    """A local host; *files* maps a path to (body, content type), the rest 404s."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?")[0]
            if path in files:
                body, ctype, status = *files[path], 200
            elif catch_all:
                body, ctype, status = CATCH_ALL_PAGE, "text/html", 200
            else:
                body, ctype, status = "not found", "text/html", 404
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args: object) -> None:
            return None

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def verify(url: str, path: str):
    finding = sensitive(url, path)
    with make_client(url) as client:
        replay([finding], client, fast_settings())
    return finding.canonical.verification


@pytest.mark.parametrize("catch_all", [False, True], ids=["normal-host", "catch-all"])
def test_content_validator_passes_without_soft404_match_is_replay_verified(catch_all):
    """Matrix: sensitive_file, content_validator, validator passes, no soft-404."""
    with host(catch_all=catch_all, files={"/.env": (ENV_BODY, "text/plain")}) as url:
        verification = verify(url, "/.env")
    assert verification.tier == T.REPLAY_VERIFIED
    assert verification.method == VerificationMethod.REPLAY
    assert verification.oracle == VerificationOracle.CONTENT_VALIDATOR
    assert verification.evidence[0].role == "probe"


@pytest.mark.parametrize("path", ["/.env", "/backup.sql"])
def test_soft404_match_on_a_catch_all_host_is_refuted(path):
    """Matrix: sensitive_file, soft404, response matches the host control."""
    with host(catch_all=True, files={}) as url:
        verification = verify(url, path)
    assert verification.tier == T.REFUTED
    assert verification.oracle == VerificationOracle.SOFT404


def test_failed_validator_is_refuted():
    """Matrix: sensitive_file, content_validator, validator fails."""
    with host(catch_all=False, files={"/.env": (LOGIN_PAGE, "text/html")}) as url:
        verification = verify(url, "/.env")
    assert verification.tier == T.REFUTED
    assert verification.oracle == VerificationOracle.CONTENT_VALIDATOR


def test_no_match_and_no_validator_stays_unverified():
    """Matrix: sensitive_file, soft404, no match and no validator."""
    files = {"/backup.zip": ("PK\x03\x04data", "application/zip")}
    with host(catch_all=False, files=files) as url:
        verification = verify(url, "/backup.zip")
    assert verification.tier == T.UNVERIFIED
    assert verification.method == VerificationMethod.REPLAY
    assert verification.oracle == VerificationOracle.CONTENT_VALIDATOR


def test_each_oracle_alone_decides_only_its_own_row():
    with host(catch_all=False, files={"/.env": (ENV_BODY, "text/plain")}) as url:
        finding = sensitive(url, "/.env").canonical
        with make_client(url) as client:
            prober = Prober(client, 50)
            soft = ORACLES["soft404"].run(finding, prober, fast_settings())
            valid = ORACLES["content_validator"].run(finding, prober, fast_settings())
    assert soft.outcome == "inconclusive"
    assert valid.outcome == "positive"


def test_sensitive_file_runs_soft404_before_content_validator():
    assert get_registry().classes["sensitive_file"].oracle == (
        "soft404, content_validator"
    )


def closed_port_url() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{sock.getsockname()[1]}"


@pytest.mark.parametrize(
    ("title", "path", "scanner", "parameter"),
    [
        ("Accessible sensitive path: /.env", "/.env", "misc_checks", ""),
        ("Cross Site Scripting", "/search?q=1", "wapiti", "q"),
    ],
    ids=["sensitive_file", "xss_reflected"],
)
def test_unreachable_target_leaves_the_finding_unverified_after_replay(
    title, path, scanner, parameter
):
    """Replay on a refused connection: unverified, method replay, no exception."""
    url = closed_port_url()
    finding = case(title, f"{url}{path}", scanner=scanner, parameter=parameter)
    with make_client(url) as client:
        report = replay([finding], client, fast_settings())
    verification = finding.canonical.verification
    assert verification.tier == T.UNVERIFIED
    assert verification.method == VerificationMethod.REPLAY
    assert verification.evidence == []
    assert report.skipped == {}


def test_replay_request_timeout_bounds_a_slow_target_and_is_restored():
    """Replay on a timeout: unverified, method replay, policy timeout restored."""
    with serve() as fx:
        slow = sensitive(fx.url, "/slow")
        with make_client(fx.url) as client:
            before = client.policy.timeout_s
            replay([slow], client, fast_settings(request_timeout_s=0.05))
            after = client.policy.timeout_s
    verification = slow.canonical.verification
    assert verification.tier == T.UNVERIFIED
    assert verification.method == VerificationMethod.REPLAY
    assert after == before


def test_verify_yaml_sets_the_replay_request_timeout():
    assert load_verify_settings().request_timeout_s == 10.0


PHPINFO_BODY = "phpinfo()\nPHP Version 8.3.0\n"
METRICS_BODY = "# HELP up up\n# TYPE up gauge\nup 1\n"


def nuclei_exposure(url: str, path: str, template_id: str) -> CorrelatedFinding:
    title = (
        "PHPinfo Page - Detect"
        if template_id == "phpinfo-files"
        else "Prometheus Metrics - Detect"
    )
    finding = Finding(
        title=title,
        description=title,
        severity=Severity.LOW,
        url=f"{url}{path}",
        method="GET",
        scanner="nuclei",
        tags=["security_misconfiguration"],
        raw_data={"template-id": template_id},
    )
    return FindingCorrelator().correlate([finding], url)[0]


def replay_nuclei(url: str, path: str, template_id: str) -> Finding:
    hit = nuclei_exposure(url, path, template_id)
    with make_client(url) as client:
        replay([hit], client, fast_settings())
    return hit.canonical


@pytest.mark.parametrize(
    ("template_id", "path", "body", "ctype"),
    [
        ("phpinfo-files", "/phpinfo.php", PHPINFO_BODY, "text/html"),
        ("prometheus-metrics", "/metrics", METRICS_BODY, "text/plain"),
    ],
)
def test_nuclei_sensitive_file_on_a_registered_path_is_replay_verified(
    template_id: str, path: str, body: str, ctype: str
) -> None:
    """Validator keys on the path; a matching body is replay_verified."""
    with host(catch_all=False, files={path: (body, ctype)}) as url:
        canonical = replay_nuclei(url, path, template_id)
    assert canonical.vuln_class == "sensitive_file"
    assert canonical.verification.tier == T.REPLAY_VERIFIED
    assert canonical.verification.oracle == VerificationOracle.CONTENT_VALIDATOR


def test_failed_validator_refutes_a_nuclei_sensitive_file() -> None:
    """A 200 body that fails the path validator is refuted, not left unverified."""
    with host(
        catch_all=False, files={"/phpinfo.php": (LOGIN_PAGE, "text/html")}
    ) as url:
        canonical = replay_nuclei(url, "/phpinfo.php", "phpinfo-files")
    assert canonical.vuln_class == "sensitive_file"
    assert canonical.verification.tier == T.REFUTED
    assert canonical.verification.oracle == VerificationOracle.CONTENT_VALIDATOR


def test_nuclei_sensitive_file_off_the_validator_registry_stays_unverified() -> None:
    """The template id does not select a validator; an unknown path stays unverified."""
    body = PHPINFO_BODY
    with host(
        catch_all=False, files={"/custom/phpinfo.php": (body, "text/html")}
    ) as url:
        canonical = replay_nuclei(url, "/custom/phpinfo.php", "phpinfo-files")
    assert canonical.vuln_class == "sensitive_file"
    assert canonical.verification.tier == T.UNVERIFIED
    assert canonical.verification.oracle == VerificationOracle.CONTENT_VALIDATOR
