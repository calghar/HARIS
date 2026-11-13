import contextlib
import importlib.util
import json
import shutil
import subprocess
import threading
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import yaml

BENCH = Path(__file__).resolve().parent.parent / "bench"
SESSION = "k3j9x2"
HEX_PARAM = "75726c"  # "url"
PATH_ID = "7"
SSRF_PATH = f"/ssrf/{SESSION}/{PATH_ID}/{HEX_PARAM}/"
DTD_PATH = f"/dtd/{SESSION}/{PATH_ID}/{HEX_PARAM}/linux.dtd"
WAPITI_TIMEOUT_SECONDS = 150
MAX_SCAN_SECONDS = 60
PUBLIC_HOST = "wapiti3"


def load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


receiver_module = load(BENCH / "fixtures" / "callback" / "server.py", "bench_receiver")
callback = load(BENCH / "callback.py", "bench_callback")
runner = load(BENCH / "run.py", "bench_run_callback")


def serve(server: ThreadingHTTPServer) -> Iterator[str]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def receiver() -> Iterator[str]:
    yield from serve(receiver_module.make_server("127.0.0.1", 0))


def read(url: str, kind: str, session: str = SESSION) -> Any:
    return httpx.get(f"{url}/get_{kind}.php", params={"session_id": session}).json()


class TestReceiverProtocol:
    def test_ssrf_callback_is_returned_in_the_shape_wapiti_reads(
        self, receiver: str
    ) -> None:
        assert httpx.get(receiver + SSRF_PATH).status_code == 200
        body = read(receiver, "ssrf")
        [record] = body[PATH_ID][HEX_PARAM]
        assert set(record) == {"url", "date", "ip", "method", "size"}
        assert record["url"] == SSRF_PATH
        assert record["method"] == "GET"
        assert record["ip"] == "127.0.0.1"

    def test_dtd_fetch_is_returned_with_payload_name_and_zero_size(
        self, receiver: str
    ) -> None:
        assert httpx.get(receiver + DTD_PATH).content == b""
        [record] = read(receiver, "xxe")[PATH_ID][HEX_PARAM]
        assert record["payload"] == "linux"
        assert record["size"] == 0

    def test_unknown_session_returns_the_nothing_received_shape(
        self, receiver: str
    ) -> None:
        httpx.get(receiver + SSRF_PATH)
        assert read(receiver, "ssrf", "zzzzzz") == {}
        assert read(receiver, "xxe") == {}
        no_session = httpx.get(f"{receiver}/get_ssrf.php")
        assert no_session.json() == {}
        assert no_session.headers["content-type"] == "application/json"

    def test_post_body_size_is_recorded(self, receiver: str) -> None:
        httpx.post(receiver + SSRF_PATH, content=b"abcd")
        [record] = read(receiver, "ssrf")[PATH_ID][HEX_PARAM]
        assert (record["method"], record["size"]) == ("POST", 4)

    def test_other_paths_answer_without_recording(self, receiver: str) -> None:
        assert httpx.get(receiver + "/").text == "ok"
        assert httpx.get(receiver + "/e.php").status_code == 200
        assert read(receiver, "ssrf") == {}

    def test_state_is_per_server(self) -> None:
        first, second = (receiver_module.make_server() for _ in range(2))
        first.store["ssrf"] = {SESSION: {}}
        assert second.store == {}
        for server in (first, second):
            server.server_close()


class TestRunnerConfig:
    def test_endpoints_use_service_name_for_target_and_host_port_for_wapiti(
        self,
    ) -> None:
        options = callback.wapiti_endpoints("http://127.0.0.1:19090")
        assert options == {
            "external_endpoint": "http://callback:9090/",
            "internal_endpoint": "http://127.0.0.1:19090/",
        }

    def test_options_land_in_the_wapiti_entry_only(self) -> None:
        config: dict[str, Any] = {
            "scanners": [
                {"name": "nikto", "options": {"timeout": 1}},
                {"name": "wapiti", "options": {"timeout": 2}},
            ]
        }
        callback.apply_wapiti_endpoints(config, {"external_endpoint": "http://x/"})
        nikto, wapiti = config["scanners"]
        assert nikto["options"] == {"timeout": 1}
        assert wapiti["options"] == {"timeout": 2, "external_endpoint": "http://x/"}

    def test_run_command_without_session_still_writes_the_endpoints_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, Any] = {}

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            seen["env"] = kwargs.get("env")
            seen["config"] = yaml.safe_load(
                Path(cmd[cmd.index("--config") + 1]).read_text()
            )
            return subprocess.CompletedProcess(cmd, 0, "", "")

        options = callback.wapiti_endpoints("http://127.0.0.1:19090")
        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        monkeypatch.setattr(runner.execute, "WAPITI_ENDPOINTS", options)
        runner.execute.run_command(["haris"], None)
        wapiti = next(s for s in seen["config"]["scanners"] if s["name"] == "wapiti")
        assert wapiti["options"]["external_endpoint"] == options["external_endpoint"]
        assert wapiti["options"]["internal_endpoint"] == options["internal_endpoint"]
        assert seen["env"] is None
        assert seen["config"]["target"]["auth"] == {"method": "none"}


class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path == "/fetch":
            target = parse_qs(parts.query).get("url", [""])[0]
            with contextlib.suppress(OSError, ValueError):
                urllib.request.urlopen(target, timeout=5).read()
            body = b"fetched"
        else:
            body = b'<html><body><a href="/fetch?url=abc">x</a></body></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.mark.skipif(shutil.which("wapiti") is None, reason="wapiti not on PATH")
def test_wapiti_reports_ssrf_through_the_local_receiver(
    receiver: str, tmp_path: Path
) -> None:
    """Out-of-band SSRF check reaches the loopback receiver, never wapiti3.ovh."""
    vulnerable = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableHandler)
    report = tmp_path / "report.json"
    for target in serve(vulnerable):
        done = subprocess.run(
            [
                "wapiti",
                "--url",
                target + "/",
                "--module",
                "ssrf",
                "--external-endpoint",
                receiver,
                "--internal-endpoint",
                receiver,
                "--max-scan-time",
                str(MAX_SCAN_SECONDS),
                "--flush-session",
                "--no-bugreport",
                "--verbose",
                "2",
                "--format",
                "json",
                "--output",
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=WAPITI_TIMEOUT_SECONDS,
            check=False,
        )
    assert PUBLIC_HOST not in done.stdout + done.stderr
    vulnerabilities = json.loads(report.read_text())["vulnerabilities"]
    assert vulnerabilities["Server Side Request Forgery"], done.stdout
