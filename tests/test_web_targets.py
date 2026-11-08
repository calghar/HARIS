from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import HTTPException

from haris.web.targets import url_host

from .test_web_env import WebEnv, stub_scan_runner
from .web_helpers import scan_count, start, verified


@pytest.fixture(autouse=True)
def _runner(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("HARIS_ALLOW_PRIVATE_TARGETS", raising=False)
    stub_scan_runner(monkeypatch)
    yield


START_MATRIX = [
    (["*.example.com"], "none", "https://app.example.com", 202),
    ([], "verified for app.example.com 3 days ago", "https://app.example.com", 202),
    ([], "verified for app.example.com 31 days ago", "https://app.example.com", 403),
    ([], "verified for example.com", "https://app.example.com", 403),
    ([], "verified by another user", "https://app.example.com", 403),
    ([], "none", "https://app.example.com", 403),
    (["*.example.com"], "none", "http://127.0.0.1:8080", 400),
    ([], "none", "http://169.254.169.254/", 400),
]


@pytest.mark.parametrize(("allowlist", "proof", "target", "status"), START_MATRIX)
def test_scan_start_matrix(
    tmp_path: Path, allowlist: list[str], proof: str, target: str, status: int
) -> None:
    """Scenario Outline: Scan start matrix."""
    env = WebEnv(tmp_path, allowlist=allowlist)
    if proof.startswith("verified for app"):
        verified(env, env.alice, "app.example.com", int(proof.split()[-3]))
    elif proof == "verified for example.com":
        verified(env, env.alice, "example.com", 1)
    elif proof == "verified by another user":
        verified(env, env.bob, "app.example.com", 1)
    before = scan_count(env)
    response = start(env, env.alice, target)
    assert response.status_code == status
    assert scan_count(env) == before + (status == 202)


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1/",
        "http://127.1.2.3:8080/",
        "http://10.0.0.5/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.100.100.200/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[fe80::1]/",
        "http://0.0.0.0/",
        "http://metadata.google.internal/",
        "http://localhost/",
        "http://internal.example.com/",
        "http://mixed.example.com/",
    ],
)
def test_ssrf_targets_are_rejected_before_scan_start(
    tmp_path: Path, target: str
) -> None:
    """Loopback, RFC1918, link-local, metadata, IPv6 and mapped IPv6 are 400."""
    env = WebEnv(tmp_path, allowlist=["*"])
    env.resolves.update(
        {
            "localhost": ["127.0.0.1"],
            "internal.example.com": ["10.0.0.9"],
            "mixed.example.com": ["93.184.216.34", "10.0.0.9"],
            "metadata.google.internal": ["93.184.216.34"],
        }
    )
    before = scan_count(env)
    response = start(env, env.alice, target)
    assert response.status_code == 400
    assert scan_count(env) == before
    assert env.proof_requests == []


def test_allow_private_in_a_request_has_no_effect(tmp_path: Path) -> None:
    """The private-target switch is server configuration, never a request field."""
    env = WebEnv(tmp_path, allowlist=["*"])
    client = env.browser(env.alice)
    before = scan_count(env)
    for extra in ({"allow_private": "true"}, {"allow_private_targets": "1"}):
        response = client.post(
            "/api/v1/scans?allow_private=true",
            data={"target_url": "http://127.0.0.1:8080", **extra},
            headers={**client.csrf_headers, "X-Allow-Private": "true"},
        )
        assert response.status_code == 400
    assert scan_count(env) == before


def test_server_policy_can_allow_private_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HARIS_ALLOW_PRIVATE_TARGETS", "true")
    env = WebEnv(tmp_path, allowlist=["*"])
    assert start(env, env.alice, "http://10.0.0.5/").status_code == 202
    assert start(env, env.alice, "http://169.254.169.254/").status_code == 400


@pytest.mark.parametrize(
    "url", ["ftp://app.example.com", "file:///etc/passwd", "//app.example.com", "x"]
)
def test_non_http_targets_are_rejected(tmp_path: Path, url: str) -> None:
    env = WebEnv(tmp_path, allowlist=["*"])
    before = scan_count(env)
    assert start(env, env.alice, url).status_code == 400
    assert scan_count(env) == before


def test_missing_target_is_rejected(tmp_path: Path) -> None:
    env = WebEnv(tmp_path)
    assert start(env, env.alice, "").status_code == 400


def test_allowlist_glob_does_not_match_the_bare_parent(tmp_path: Path) -> None:
    env = WebEnv(tmp_path, allowlist=["*.example.com"])
    assert start(env, env.alice, "https://example.com").status_code == 403
    assert start(env, env.alice, "https://evil-example.com").status_code == 403
    assert start(env, env.alice, "https://APP.Example.com").status_code == 202


def test_url_host_normalises_case_and_trailing_dot() -> None:
    assert url_host("https://APP.Example.com./x") == "app.example.com"
    with pytest.raises(HTTPException):
        url_host("mailto:a@example.com")
