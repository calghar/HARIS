from pathlib import Path
from typing import Any

import pytest

from haris.models import ScannerResult, Target
from haris.models.scan_context import ScanContext
from haris.verify import DEFAULT_VERIFY_MODE, VerifyMode
from haris.web.scan_runtime import ScanJobParams
from haris.web.settings import VERIFY_DEFAULT_ENV, WebSettings

from .test_verify_pipeline import Stub, xss_at
from .test_web_env import WebEnv, wait_for
from .test_web_execute import RecordingRunner, real_execute  # noqa: F401
from .verify_server import serve
from .web_helpers import TARGET_URL, job_status, status

JOB_PARAMS: dict[str, Any] = {
    "target_url": "https://app.example.com",
    "profile_name": "quick",
    "report_formats": ["json"],
    "rate_limit": 10.0,
    "max_requests": 100,
}


def _post(env: WebEnv, **fields: str) -> Any:
    client = env.browser(env.alice)
    return client.post(
        "/api/v1/scans",
        data={"target_url": TARGET_URL} | fields,
        headers=client.csrf_headers,
    )


def _start(env: WebEnv, **fields: str) -> str:
    response = _post(env, **fields)
    assert response.status_code == 202, response.text
    scan_id: str = response.json()["scan_id"]
    return scan_id


def _stage_log(env: WebEnv, scan_id: str) -> list[str]:
    session = env.state.store.load_session(scan_id)
    assert session is not None
    return session.stage_log


def _local_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, url: str, **extra: str
) -> tuple[WebEnv, str]:
    class WebStub(Stub):
        def __init__(self, options: dict[str, Any] | None = None) -> None:
            super().__init__([xss_at(f"{url}/search?q=1")])

        def scan(
            self, target: Target, context: ScanContext | None = None
        ) -> ScannerResult:
            return ScannerResult(scanner_name="wapiti", findings=list(self.findings))

    monkeypatch.setenv("HARIS_ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setattr("haris.core.runner.all_registered", lambda: {"wapiti": WebStub})
    env = WebEnv(tmp_path, allowlist=["127.0.0.1"])
    scan_id = _start(env, target_url=url, profile="full", rate_limit="1000", **extra)
    wait_for(lambda: status(env, scan_id) in {"completed", "incomplete", "failed"})
    return env, scan_id


def test_web_scan_without_verify_runs_the_replay_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scan created from the web with no verify field runs the replay stage."""
    with serve() as fixture:
        env, scan_id = _local_scan(tmp_path, monkeypatch, fixture.url)
        replayed = [path for _, path in fixture.seen if "/search" in path]
    assert "replay" in _stage_log(env, scan_id)
    assert replayed


def test_web_scan_with_verify_off_has_no_replay_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scan with verify off has no replay stage and sends no replay request."""
    with serve() as fixture:
        env, scan_id = _local_scan(tmp_path, monkeypatch, fixture.url, verify="off")
        replayed = [path for _, path in fixture.seen if "/search" in path]
    assert "replay" not in _stage_log(env, scan_id)
    assert not replayed


def test_replay_target_must_pass_the_ssrf_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the server's private-target flag a loopback target is refused."""
    monkeypatch.delenv("HARIS_ALLOW_PRIVATE_TARGETS", raising=False)
    env = WebEnv(tmp_path, allowlist=["127.0.0.1"])
    response = _post(env, target_url="http://127.0.0.1:9/", verify="replay")
    assert response.status_code == 400


def test_stored_job_without_verify_loads_and_uses_the_server_default(
    tmp_path: Path,
    real_execute: type[RecordingRunner],  # noqa: F811
) -> None:
    assert ScanJobParams.model_validate(JOB_PARAMS).verify is None
    env = WebEnv(tmp_path)
    env.settings.verify_default = VerifyMode.OFF
    env.state.jobs.submit(
        "old00001",
        env.alice.user_id,
        JOB_PARAMS,
        target_url=JOB_PARAMS["target_url"],
        profile_name="quick",
        template_id="",
    )
    wait_for(lambda: job_status(env, "old00001").value == "completed")
    assert real_execute.instances[0].kwargs["verify"] is VerifyMode.OFF


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({}, None),
        ({"verify": "replay"}, VerifyMode.REPLAY),
        ({"verify": "off"}, VerifyMode.OFF),
        ({"verify": "llm", "llm_enrich": "1"}, VerifyMode.LLM),
    ],
)
def test_api_accepts_verify_and_passes_it_to_the_runner(
    tmp_path: Path,
    real_execute: type[RecordingRunner],  # noqa: F811
    extra: dict[str, str],
    expected: VerifyMode | None,
) -> None:
    env = WebEnv(tmp_path)
    scan_id = _start(env, **extra)
    job = env.state.store.jobs.get(scan_id)
    assert job is not None
    assert job.params["verify"] == (expected.value if expected else None)
    wait_for(lambda: status(env, scan_id) == "completed")
    sent = real_execute.instances[0].kwargs["verify"]
    assert sent is (expected or DEFAULT_VERIFY_MODE)


@pytest.mark.parametrize(
    "extra", [{"verify": "bogus"}, {"verify": "LLM"}, {"verify": "llm"}]
)
def test_invalid_verify_is_a_422_and_creates_no_scan(
    tmp_path: Path, extra: dict[str, str]
) -> None:
    env = WebEnv(tmp_path)
    before = len(env.state.store.list_sessions())
    assert _post(env, **extra).status_code == 422
    assert len(env.state.store.list_sessions()) == before


def test_server_default_comes_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(VERIFY_DEFAULT_ENV, raising=False)
    assert WebSettings.from_env().verify_default is VerifyMode.REPLAY
    monkeypatch.setenv(VERIFY_DEFAULT_ENV, "off")
    assert WebSettings.from_env().verify_default is VerifyMode.OFF
    monkeypatch.setenv(VERIFY_DEFAULT_ENV, "bogus")
    with pytest.raises(ValueError, match="bogus"):
        WebSettings.from_env()
