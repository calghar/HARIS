from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import requests

from .fake_transport import Reply
from .test_web_env import WebEnv, stub_scan_runner
from .web_helpers import (
    FIXED_NOW,
    PROOF_TOKEN,
    TOKEN_FORMAT,
    WELL_KNOWN,
    issue,
    proof_hosts,
    start,
    verified,
    verify,
)


@pytest.fixture(autouse=True)
def _runner(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("HARIS_ALLOW_PRIVATE_TARGETS", raising=False)
    stub_scan_runner(monkeypatch)
    yield


def test_proof_token_has_the_specified_shape_and_is_per_user_and_host(
    tmp_path: Path,
) -> None:
    env = WebEnv(tmp_path)
    alice, bob = env.browser(env.alice), env.browser(env.bob)
    first = issue(alice)
    assert TOKEN_FORMAT.match(str(first["proof_token"]))
    assert issue(alice)["proof_token"] == first["proof_token"]
    assert issue(bob)["proof_token"] != first["proof_token"]
    assert issue(alice, "other.example.com")["proof_token"] != first["proof_token"]
    assert first["dns_name"] == "_haris-verify.app.example.com"
    assert first["file_path"] == WELL_KNOWN
    assert first["verified"] is False


def test_file_proof_does_not_follow_redirects(tmp_path: Path) -> None:
    """Scenario: File proof does not follow redirects."""
    env = WebEnv(tmp_path, allowlist=[])

    def handler(request: requests.PreparedRequest) -> Reply:
        assert request.path_url == WELL_KNOWN
        return 302, {"Location": "https://attacker.test/token.txt"}, b""

    env.proof_handler = handler
    alice = env.browser(env.alice)
    issue(alice)
    result = verify(alice)
    assert result.status_code == 200
    assert result.json()["verified"] is False
    assert proof_hosts(env) == {"app.example.com"}
    assert "attacker.test" not in env.resolves
    assert start(env, env.alice, "https://app.example.com").status_code == 403


def test_file_proof_redirect_to_a_private_address_is_not_followed(
    tmp_path: Path,
) -> None:
    env = WebEnv(tmp_path, allowlist=[])
    env.proof_handler = lambda _r: (302, {"Location": "http://127.0.0.1/t.txt"}, b"")
    alice = env.browser(env.alice)
    issue(alice)
    assert verify(alice).json()["verified"] is False
    assert len(env.proof_requests) == 1


def test_file_proof_accepts_the_stripped_token(tmp_path: Path) -> None:
    env = WebEnv(tmp_path, allowlist=[])
    alice = env.browser(env.alice)
    token = str(issue(alice)["proof_token"])
    env.proof_handler = lambda _r: (200, {}, f"  {token}\n".encode())
    result = verify(alice).json()
    assert result["verified"] is True
    assert result["method"] == "file"
    request = env.proof_requests[0]
    assert request.method == "GET"
    assert request.path_url == WELL_KNOWN
    assert start(env, env.alice, "https://app.example.com").status_code == 202


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (200, b"haris-verify=ffffffffffffffffffffffffffffffff"),
        (200, b""),
        (404, b"{token}"),
        (500, b"{token}"),
        (200, b"prefix {token}"),
    ],
)
def test_file_proof_rejects_wrong_content_or_status(
    tmp_path: Path, status: int, body: bytes
) -> None:
    env = WebEnv(tmp_path, allowlist=[])
    alice = env.browser(env.alice)
    token = str(issue(alice)["proof_token"])
    content = body.replace(b"{token}", token.encode())
    env.proof_handler = lambda _r: (status, {}, content)
    assert verify(alice).json()["verified"] is False


def test_another_users_token_does_not_verify_the_host(tmp_path: Path) -> None:
    env = WebEnv(tmp_path, allowlist=[])
    alice, bob = env.browser(env.alice), env.browser(env.bob)
    token = str(issue(alice)["proof_token"])
    issue(bob)
    env.proof_handler = lambda _r: (200, {}, token.encode())
    assert verify(bob).json()["verified"] is False
    assert verify(alice).json()["verified"] is True


def test_dns_proof(tmp_path: Path) -> None:
    """Scenario: DNS proof."""
    env = WebEnv(tmp_path, allowlist=[])
    env.use_targets(
        txt_lookup=lambda name: (
            [PROOF_TOKEN] if name == "_haris-verify.app.example.com" else []
        ),
        clock=lambda: FIXED_NOW,
    )
    env.state.store.targets.add(
        env.alice.user_id, "app.example.com", PROOF_TOKEN, "2026-11-01T00:00:00+00:00"
    )
    result = verify(env.browser(env.alice))
    assert result.status_code == 200
    row = env.state.store.targets.get(env.alice.user_id, "app.example.com")
    assert row is not None
    assert row.verified_at == FIXED_NOW.isoformat(timespec="seconds")
    assert row.method == "dns"
    assert env.proof_requests == []


def test_dns_proof_on_the_host_itself(tmp_path: Path) -> None:
    env = WebEnv(tmp_path, allowlist=[])
    env.use_targets(txt_lookup=lambda name: [PROOF_TOKEN, "v=spf1 -all"])
    env.state.store.targets.add(
        env.alice.user_id, "app.example.com", PROOF_TOKEN, "2026-11-01T00:00:00+00:00"
    )
    assert verify(env.browser(env.alice)).json()["verified"] is True


def test_dns_proof_covers_only_the_exact_host(tmp_path: Path) -> None:
    """A record on the parent domain does not verify a sub-host."""
    env = WebEnv(tmp_path, allowlist=[])
    queried: list[str] = []

    def lookup(name: str) -> list[str]:
        queried.append(name)
        return [PROOF_TOKEN] if name == "example.com" else []

    env.use_targets(txt_lookup=lookup)
    env.state.store.targets.add(
        env.alice.user_id, "app.example.com", PROOF_TOKEN, "2026-11-01T00:00:00+00:00"
    )
    assert verify(env.browser(env.alice)).json()["verified"] is False
    assert queried == ["app.example.com", "_haris-verify.app.example.com"]


def test_dns_proof_with_a_wrong_token_fails(tmp_path: Path) -> None:
    env = WebEnv(tmp_path, allowlist=[])
    env.use_targets(txt_lookup=lambda name: ["haris-verify=" + "0" * 32])
    alice = env.browser(env.alice)
    issue(alice)
    assert verify(alice).json()["verified"] is False


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "169.254.169.254", "10.1.2.3", "::1", "internal.example.com"]
)
def test_ssrf_guard_runs_before_any_proof_lookup(tmp_path: Path, host: str) -> None:
    env = WebEnv(tmp_path, allowlist=[])
    looked_up: list[str] = []
    env.resolves["internal.example.com"] = ["10.0.0.9"]

    def lookup(name: str) -> list[str]:
        looked_up.append(name)
        return []

    env.use_targets(txt_lookup=lookup)
    path_host = f"[{host}]" if ":" in host else host
    alice = env.browser(env.alice)
    assert verify(alice, path_host).status_code in {400, 422}
    response = alice.post(
        "/api/v1/targets", json={"host": host}, headers=alice.csrf_headers
    )
    assert response.status_code in {400, 422}
    assert looked_up == []
    assert env.proof_requests == []
    assert env.state.store.targets.list_for_user(env.alice.user_id) == []


def test_invalid_host_values_are_rejected(tmp_path: Path) -> None:
    env = WebEnv(tmp_path)
    alice = env.browser(env.alice)
    for host in ("a b", "app.example.com/x", "app.example.com:8080", "-x.test", ""):
        response = alice.post(
            "/api/v1/targets", json={"host": host}, headers=alice.csrf_headers
        )
        assert response.status_code == 422, host


def test_targets_are_listed_and_deleted_per_user(tmp_path: Path) -> None:
    env = WebEnv(tmp_path)
    alice, bob = env.browser(env.alice), env.browser(env.bob)
    issue(alice)
    assert [t["host"] for t in alice.get("/api/v1/targets").json()] == [
        "app.example.com"
    ]
    assert bob.get("/api/v1/targets").json() == []
    assert (
        bob.delete("/api/v1/targets/app.example.com", headers=bob.csrf_headers)
    ).status_code == 404
    deleted = alice.delete(
        "/api/v1/targets/app.example.com", headers=alice.csrf_headers
    )
    assert deleted.status_code == 204
    assert alice.get("/api/v1/targets").json() == []


def test_target_routes_need_the_targets_scope(tmp_path: Path) -> None:
    env = WebEnv(tmp_path)
    read_only = env.bearer(env.alice, ("scans:read", "scans:write"))
    assert read_only.get("/api/v1/targets").status_code == 403
    allowed = env.bearer(env.alice, ("targets:write",))
    assert allowed.get("/api/v1/targets").status_code == 200
    assert (
        allowed.post("/api/v1/targets", json={"host": "app.example.com"}).status_code
        == 200
    )


def test_expired_verification_must_be_repeated(tmp_path: Path) -> None:
    env = WebEnv(tmp_path, allowlist=[])
    verified(env, env.alice, "app.example.com", 29)
    assert start(env, env.alice, "https://app.example.com").status_code == 202
    env.state.store.targets.mark_verified(
        env.alice.user_id,
        "app.example.com",
        "dns",
        (datetime.now(UTC) - timedelta(days=31)).isoformat(timespec="seconds"),
    )
    assert start(env, env.alice, "https://app.example.com").status_code == 403
