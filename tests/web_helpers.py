import re
from datetime import UTC, datetime, timedelta
from typing import Any

from haris.auth.models import User
from haris.db.jobs import JobStatus

from .test_web_env import Browser, WebEnv

TOKEN_FORMAT = re.compile(r"^haris-verify=[0-9a-f]{32}$")
WELL_KNOWN = "/.well-known/haris-verify.txt"
FIXED_NOW = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)
PROOF_TOKEN = "haris-verify=0123456789abcdef0123456789abcdef"
TARGET_URL = "https://app.example.com"
HOST = "app.example.com"
SETTLE_S = 0.3


def start(
    env: WebEnv, user: User | None = None, url: str = TARGET_URL, **extra: str
) -> Any:
    client = env.browser(user or env.alice)
    return client.post(
        "/api/v1/scans",
        data={"target_url": url, **extra},
        headers=client.csrf_headers,
    )


def start_scan(env: WebEnv, user: User | None = None, **extra: str) -> str:
    response = start(env, user, **extra)
    assert response.status_code == 202, response.text
    scan_id: str = response.json()["scan_id"]
    return scan_id


def verified(env: WebEnv, user: User, host: str, days_ago: int) -> None:
    repo = env.state.store.targets
    repo.add(user.user_id, host, PROOF_TOKEN, FIXED_NOW.isoformat(timespec="seconds"))
    when = datetime.now(UTC) - timedelta(days=days_ago)
    repo.mark_verified(user.user_id, host, "dns", when.isoformat(timespec="seconds"))


def scan_count(env: WebEnv) -> int:
    return len(env.state.store.list_sessions())


def proof_hosts(env: WebEnv) -> set[str]:
    return {r.headers["Host"] for r in env.proof_requests}


def issue(client: Browser, host: str = HOST) -> dict[str, object]:
    response = client.post(
        "/api/v1/targets", json={"host": host}, headers=client.csrf_headers
    )
    assert response.status_code == 200, response.text
    body: dict[str, object] = response.json()
    return body


def verify(client: Browser, host: str = HOST) -> Any:
    return client.post(f"/api/v1/targets/{host}/verify", headers=client.csrf_headers)


def status(env: WebEnv, scan_id: str) -> str:
    response = env.browser(env.admin).get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 200
    value: str = response.json()["status"]
    return value


def job_status(env: WebEnv, scan_id: str) -> JobStatus:
    job = env.state.store.jobs.get(scan_id)
    assert job is not None
    return job.status


def cancel(env: WebEnv, user: User, scan_id: str) -> Any:
    client = env.browser(user)
    return client.post(f"/api/v1/scans/{scan_id}/cancel", headers=client.csrf_headers)
