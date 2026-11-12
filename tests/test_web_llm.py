import logging
from pathlib import Path
from typing import Any

import pytest

from haris.llm.budget import BudgetExceededError
from haris.models import LLMResponse, ScanSession

from .test_web_env import Browser, WebEnv

SECRET = "sk-live-secret-value"
ROUTES = [
    ("/api/v1/llm/ask", {"question": "q"}),
    ("/api/v1/llm/chat", {"question": "q"}),
    ("/api/v1/llm/summarize", {}),
    ("/api/v1/llm/explain", {"finding_id": "f1"}),
    ("/api/v1/llm/remediation-plan", {}),
    ("/api/v1/llm/test-cases", {}),
    ("/api/v1/llm/mitigations", {}),
    ("/api/v1/llm/filter-findings", {"criteria": "high"}),
]
FAILURES = [
    (BudgetExceededError(f"budget spent {SECRET}"), 429, "LLM budget exceeded"),
    (ImportError(f"No module named {SECRET}"), 501, "LLM backend not available"),
    (RuntimeError(f"upstream rejected {SECRET}"), 500, "LLM request failed"),
]


@pytest.fixture()
def env(tmp_path: Path) -> WebEnv:
    return WebEnv(tmp_path)


def post(client: Browser, path: str, body: dict[str, Any]) -> Any:
    return client.post(path, json=body, headers=client.csrf_headers)


@pytest.mark.parametrize(("path", "extra"), ROUTES)
@pytest.mark.parametrize(("error", "status", "detail"), FAILURES)
def test_llm_failures_are_generic_and_logged(
    env: WebEnv,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    path: str,
    extra: dict[str, Any],
    error: Exception,
    status: int,
    detail: str,
) -> None:
    """Budget errors render as 429; no response ever carries `str(exc)`."""

    def failing(_llm: Any, _name: str | None = None, **_kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr("haris.web.llm_support.create_backend_from_config", failing)
    scan = env.add_scan(env.alice)
    alice = env.browser(env.alice)
    with caplog.at_level(logging.WARNING):
        response = post(alice, path, {"scan_id": scan, "backend": "x", **extra})
    assert response.status_code == status
    assert response.json() == {"detail": detail}
    assert SECRET not in response.text
    assert SECRET in caplog.text


class FakeQA:
    """Stands in for `ReportQA`: answers without a backend."""

    def reply(self, text: str) -> LLMResponse:
        return LLMResponse(text=text, model="fake", usage={"total_tokens": 7})

    def ask(self, _session: ScanSession, question: str) -> LLMResponse:
        return self.reply(f"answer:{question}")

    def chat(self, _session: ScanSession, question: str, _history: Any) -> LLMResponse:
        return self.reply(f"chat:{question}")

    def summarize(self, _session: ScanSession, **_kw: Any) -> LLMResponse:
        return self.reply("summary")


@pytest.fixture()
def fake_qa(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("haris.web.routers.llm_chat.make_qa", lambda _b=None: FakeQA())
    monkeypatch.setattr("haris.web.routers.llm_scan.make_qa", lambda _b=None: FakeQA())
    monkeypatch.setattr(
        "haris.web.routers.llm_chat.get_default_backend_name", lambda: "fake"
    )


@pytest.mark.usefixtures("fake_qa")
def test_ask_and_summarize_return_declared_models(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    alice = env.browser(env.alice)
    asked = post(alice, "/api/v1/llm/ask", {"scan_id": scan, "question": "why"})
    assert asked.json() == {"answer": "answer:why", "model": "fake", "tokens": 7}
    summary = post(alice, "/api/v1/llm/summarize", {"scan_id": scan})
    assert summary.json()["answer"] == "summary"


@pytest.mark.usefixtures("fake_qa")
def test_blank_question_is_rejected(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    alice = env.browser(env.alice)
    for question in ("", "   "):
        response = post(
            alice, "/api/v1/llm/ask", {"scan_id": scan, "question": question}
        )
        assert response.status_code == 422


@pytest.mark.usefixtures("fake_qa")
def test_chat_flow_and_conversation_listing(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    alice, bob, admin = (env.browser(u) for u in (env.alice, env.bob, env.admin))
    first = post(alice, "/api/v1/llm/chat", {"scan_id": scan, "question": "one"}).json()
    cid = first["conversation_id"]
    second = post(
        alice,
        "/api/v1/llm/chat",
        {"scan_id": scan, "question": "two", "conversation_id": cid},
    ).json()
    assert second["conversation_id"] == cid
    assert (second["message_count"], second["total_tokens"]) == (4, 14)

    listing = alice.get("/api/v1/llm/conversations").json()
    assert [c["conversation_id"] for c in listing] == [cid]
    assert listing[0]["scan_id"] == scan
    assert listing[0]["message_count"] == 4
    assert bob.get("/api/v1/llm/conversations").json() == []
    assert [
        c["conversation_id"] for c in admin.get("/api/v1/llm/conversations").json()
    ] == [cid]

    detail = alice.get(f"/api/v1/llm/conversations/{cid}").json()
    assert [m["role"] for m in detail["messages"]] == ["user", "assistant"] * 2
    assert bob.get(f"/api/v1/llm/conversations/{cid}").status_code == 404
    gone = alice.delete(f"/api/v1/llm/conversations/{cid}", headers=alice.csrf_headers)
    assert gone.json() == {"deleted": cid}
    assert alice.get("/api/v1/llm/conversations").json() == []


@pytest.mark.usefixtures("fake_qa")
def test_conversation_listing_hides_conversations_of_scans_no_longer_visible(
    env: WebEnv,
) -> None:
    scan = env.add_scan(env.alice)
    env.add_conversation(env.alice, scan)
    assert len(env.browser(env.alice).get("/api/v1/llm/conversations").json()) == 1
    alice = env.browser(env.alice)
    alice.delete(f"/api/v1/scans/{scan}", headers=alice.csrf_headers)
    assert alice.get("/api/v1/llm/conversations").json() == []


@pytest.mark.usefixtures("fake_qa")
def test_unknown_conversation_id_starts_a_new_conversation(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    body = post(
        env.browser(env.alice),
        "/api/v1/llm/chat",
        {"scan_id": scan, "question": "q", "conversation_id": "nope"},
    ).json()
    assert body["conversation_id"] != "nope"


def test_llm_routes_need_the_write_scope_for_tokens(env: WebEnv) -> None:
    read_only = env.bearer(env.alice)
    assert read_only.get("/api/v1/llm/backends").status_code == 200
    assert read_only.get("/api/v1/llm/conversations").status_code == 200
    scan = env.add_scan(env.alice)
    blocked = read_only.post("/api/v1/llm/ask", json={"scan_id": scan, "question": "q"})
    assert blocked.status_code == 403


def test_backends_listing_uses_the_declared_model(
    env: WebEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    def entries(_model: str = "") -> list[dict[str, Any]]:
        return [
            {"name": "litellm", "available": True, "reason": ""},
            {"name": "other", "available": False, "reason": "not installed"},
        ]

    monkeypatch.setattr("haris.web.routers.llm_chat.get_available_backends", entries)
    monkeypatch.setattr(
        "haris.web.routers.llm_chat.get_default_backend_name", lambda: "litellm"
    )
    body = env.browser(env.alice).get("/api/v1/llm/backends").json()
    assert body["default"] == "litellm"
    assert body["backends"][1] == {
        "name": "other",
        "available": False,
        "reason": "not installed",
        "model": "",
        "endpoint": "",
    }
