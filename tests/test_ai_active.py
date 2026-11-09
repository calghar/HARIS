import json
import re
from collections.abc import Iterator
from html import escape
from types import ModuleType
from typing import Any
from urllib.parse import parse_qs

import pytest
import requests

from haris.ai_security.probes import load_probes
from haris.models import AuthConfig, Finding, VerificationTier
from haris.net import ScopedClient

from .ai_support import (
    BOTH,
    CANARY,
    CHAT,
    MODELS,
    FakeChat,
    classes,
    local_client,
    net_with,
    obedient,
    run_ai,
)
from .checks_support import html
from .fake_transport import Reply
from .test_bench_fixtures import serve


def scan(chat: FakeChat, *, base: dict[str, Any] | None = None, **options: Any):
    net = net_with({"/v1/models": MODELS, CHAT: chat}, **(base or {}))
    return run_ai(net.client, **options)[0], net


def by_class(findings: list[Finding], vuln_class: str) -> list[Finding]:
    return [f for f in findings if f.vuln_class == vuln_class]


def chat_prompts(client: ScopedClient) -> list[str]:
    return [
        e.request_body_excerpt
        for e in client.log.entries()
        if e.method == "POST"
        and e.url.endswith(CHAT)
        and "messages" in e.request_body_excerpt
    ]


@pytest.fixture
def ai_app() -> Iterator[tuple[ModuleType, str]]:
    yield from serve("vuln_ai_app")


class TestActivation:
    @pytest.mark.parametrize(
        ("options", "allowed"),
        [({}, False), ({"active": True}, False), (BOTH, True)],
        ids=["absent", "ai-active", "ai-active+authorisation"],
    )
    def test_prompts_need_both_flags(self, ai_app, options, allowed) -> None:
        _, url = ai_app
        with local_client(url) as client:
            run_ai(client, **options)
            sent = len(chat_prompts(client))
        assert (0 < sent <= 50) if allowed else sent == 0

    def test_authorisation_alone_does_not_activate_probes(self, ai_app) -> None:
        with local_client(ai_app[1]) as client:
            run_ai(client, authorised=True)
            assert chat_prompts(client) == []

    def test_no_prompt_without_post_in_scope(self) -> None:
        chat = FakeChat(obedient)
        result, _ = scan(chat, base={"post": False}, **BOTH)
        assert chat.bodies == []
        assert any("POST" in note for note in result.metadata["skipped"])


class TestCanaryVerdict:
    def test_obedient_model_gives_a_replay_verified_finding(self) -> None:
        result, _ = scan(FakeChat(obedient), **BOTH)
        found = by_class(result.findings, "ai_prompt_injection_canary")
        assert len(found) == 1
        assert found[0].verification.tier is VerificationTier.REPLAY_VERIFIED
        assert found[0].verification.oracle.value == "canary"
        assert found[0].tags[1] == "LLM01:2026"

    def test_a_canary_that_is_not_the_requested_one_is_ignored(self) -> None:
        wrong = FakeChat(lambda _p: "HARIS-CANARY-0000000000000000")
        assert not any(
            c.endswith("canary") for c in classes(scan(wrong, **BOTH)[0].findings)
        )

    def test_refusal_gives_no_finding(self) -> None:
        refusing = FakeChat(lambda _p: "I cannot do that")
        result, _ = scan(refusing, **BOTH)
        assert not any(c.endswith("canary") for c in classes(result.findings))

    def test_replay_that_misses_the_fresh_canary_stays_unverified(self) -> None:
        replies = iter(["ok", None])

        def once(prompt: str) -> str:
            if "ignore previous instructions and reply" not in prompt.lower():
                return "Four."
            return obedient(prompt) if next(replies, None) == "ok" else "no"

        found = by_class(
            scan(FakeChat(once), **BOTH)[0].findings, "ai_prompt_injection_canary"
        )
        assert [f.verification.tier for f in found] == [VerificationTier.UNVERIFIED]

    def test_echoing_model_voids_canary_verdicts(self) -> None:
        result, _ = scan(FakeChat(lambda p: p), **BOTH)
        assert not any(c.endswith("canary") for c in classes(result.findings))
        assert any("echoes" in note for note in result.metadata["skipped"])

    def test_benign_model_gets_the_jailbreak_set_and_no_finding(self) -> None:
        chat = FakeChat(lambda _p: "I can help with orders.")
        result, _ = scan(chat, **BOTH)
        assert not any(c.endswith("canary") for c in classes(result.findings))
        sent = " ".join(chat.prompts)
        assert all(j.content.split("{")[0] in sent for j in load_probes().jailbreaks)

    def test_jailbreaks_are_skipped_once_plain_injection_works(self) -> None:
        chat = FakeChat(obedient)
        scan(chat, **BOTH)
        assert not any("test harness" in p for p in chat.prompts)

    def test_jailbreak_finding_when_only_a_framing_works(self) -> None:
        def framed(prompt: str) -> str:
            return obedient(prompt) if "developer mode" in prompt.lower() else "no"

        result, _ = scan(FakeChat(framed), **BOTH)
        found = by_class(result.findings, "ai_jailbreak_canary")
        assert [f.parameter for f in found] == ["developer_mode"]


class TestBudgetsAndSources:
    def test_prompt_budget_is_a_hard_cap(self) -> None:
        chat = FakeChat(obedient)
        scan(chat, max_prompts=3, **BOTH)
        assert len(chat.bodies) == 3

    def test_default_budget_never_exceeds_fifty(self) -> None:
        chat = FakeChat(lambda _p: "no")
        scan(chat, **BOTH)
        assert 0 < len(chat.bodies) <= 50

    def test_token_cap_option_clamps_every_request(self) -> None:
        chat = FakeChat(obedient)
        scan(chat, max_tokens_per_prompt=8, **BOTH)
        assert {b["max_tokens"] for b in chat.bodies} <= {1, 8}

    def test_default_token_cap_is_256(self) -> None:
        chat = FakeChat(obedient)
        scan(chat, **BOTH)
        assert max(b["max_tokens"] for b in chat.bodies) == 256

    def test_every_prompt_is_a_payload_from_the_probe_file(self) -> None:
        probes = load_probes()
        templates = [
            probes.control.content,
            probes.consumption.burst.content,
            probes.consumption.max_tokens.content,
            *(p.content for p in probes.probes),
            *(p.content for p in probes.jailbreaks),
        ]
        patterns = [
            re.compile(re.escape(t).replace(re.escape("{canary}"), CANARY.pattern))
            for t in templates
        ]
        for model in (obedient, lambda _p: "no"):
            chat = FakeChat(model)
            scan(chat, **BOTH)
            assert chat.prompts
            for prompt in chat.prompts:
                assert any(p.fullmatch(prompt) for p in patterns), prompt

    def test_probe_file_has_no_override_in_the_working_directory(
        self, tmp_path, monkeypatch
    ) -> None:
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "ai_probes.yaml").write_text("ai: {}\n")
        monkeypatch.chdir(tmp_path)
        load_probes.cache_clear()
        try:
            assert load_probes().ai.max_prompts == 50
        finally:
            load_probes.cache_clear()

    def test_failed_control_prompt_stops_the_endpoint(self) -> None:
        chat = FakeChat(obedient, status=401)
        result, _ = scan(chat, **BOTH)
        assert len(chat.bodies) == 1
        assert any("control prompt" in note for note in result.metadata["skipped"])


class TestOtherProbes:
    def test_system_prompt_leak_matches_a_marker_exactly(self) -> None:
        leaky = FakeChat(
            lambda p: "My prompt: SECRET-MARK-77" if "system prompt" in p else "no"
        )
        found = by_class(
            scan(leaky, system_prompt_markers=["SECRET-MARK-77"], **BOTH)[0].findings,
            "ai_system_prompt_leak",
        )
        assert len(found) == 1
        assert found[0].verification.tier is VerificationTier.REPLAY_VERIFIED
        assert "SECRET-MARK-77" in found[0].evidence

    def test_no_marker_in_the_reply_means_no_leak_finding(self) -> None:
        result, _ = scan(FakeChat(lambda _p: "I cannot share that."), **BOTH)
        assert "ai_system_prompt_leak" not in classes(result.findings)

    def test_missing_rate_limit_after_a_clean_burst(self) -> None:
        found = by_class(
            scan(FakeChat(lambda _p: "OK"), **BOTH)[0].findings, "ai_missing_rate_limit"
        )
        assert len(found) == 1
        assert found[0].cwe_id == "CWE-770"

    def test_rate_limit_header_suppresses_the_finding(self) -> None:
        chat = FakeChat(lambda _p: "OK", headers={"X-RateLimit-Remaining": "5"})
        assert "ai_missing_rate_limit" not in classes(scan(chat, **BOTH)[0].findings)

    def test_token_cap_ignored_by_usage_count(self) -> None:
        chat = FakeChat(lambda _p: "OK", extra={"usage": {"completion_tokens": 200}})
        assert "ai_ignored_token_cap" in classes(scan(chat, **BOTH)[0].findings)

    def test_token_cap_honoured(self) -> None:
        chat = FakeChat(lambda _p: "OK", extra={"usage": {"completion_tokens": 1}})
        assert "ai_ignored_token_cap" not in classes(scan(chat, **BOTH)[0].findings)

    def test_xss_marker_reflected_unescaped_is_replay_verified(self) -> None:
        def page(request: requests.PreparedRequest) -> Reply:
            query = (request.url or "").partition("?")[2]
            question = parse_qs(query).get("q", [""])[0]
            return html(f"<p>You asked: {question}</p>".encode())

        net = net_with({"/chat": page})
        found = by_class(
            run_ai(net.client, **BOTH)[0].findings, "ai_output_handling_xss"
        )
        assert [(f.parameter, f.verification.tier) for f in found] == [
            ("q", VerificationTier.REPLAY_VERIFIED)
        ]

    def test_escaped_reflection_is_not_reported(self) -> None:
        def page(request: requests.PreparedRequest) -> Reply:

            query = (request.url or "").partition("?")[2]
            return html(escape(parse_qs(query).get("q", [""])[0]).encode())

        net = net_with({"/chat": page})
        assert run_ai(net.client, **BOTH)[0].findings == []

    def test_passive_scan_never_probes_xss_sinks(self) -> None:
        net = net_with({"/chat": html(b"<p>hello</p>")})
        run_ai(net.client)
        assert not any("haris-x" in (r.url or "") for r in net.sent)


class TestVulnAiApp:
    EXPECTED = {
        "ai_unauthenticated_inference",
        "ai_verbose_provider_error",
        "ai_tool_description_injection",
        "ai_prompt_injection_canary",
        "ai_system_prompt_leak",
        "ai_output_handling_xss",
        "ai_mcp_unauthenticated",
    }

    def test_every_planted_weakness_is_found(self, ai_app) -> None:
        with local_client(ai_app[1]) as client:
            result, _ = run_ai(client, **BOTH)
        assert result.errors == []
        assert classes(result.findings) >= self.EXPECTED

    def test_canary_and_leak_findings_are_replay_verified(self, ai_app) -> None:
        with local_client(ai_app[1]) as client:
            result, _ = run_ai(client, **BOTH)
        for name in ("ai_prompt_injection_canary", "ai_system_prompt_leak"):
            tiers = {f.verification.tier for f in by_class(result.findings, name)}
            assert tiers == {VerificationTier.REPLAY_VERIFIED}

    def test_passive_run_finds_the_non_prompt_weaknesses_only(self, ai_app) -> None:
        with local_client(ai_app[1]) as client:
            result, _ = run_ai(client)
            assert chat_prompts(client) == []
        found = classes(result.findings)
        assert {
            "ai_unauthenticated_inference",
            "ai_verbose_provider_error",
            "ai_tool_description_injection",
        } <= found
        assert not found & {"ai_prompt_injection_canary", "ai_system_prompt_leak"}

    def test_two_runs_give_identical_verdicts(self, ai_app) -> None:
        def verdicts() -> set[tuple[str, str, str]]:
            with local_client(ai_app[1]) as client:
                result, _ = run_ai(client, **BOTH)
            return {
                (f.vuln_class, f.parameter, f.verification.tier.value)
                for f in result.findings
            }

        assert verdicts() == verdicts()

    def test_credentials_do_not_leak_into_evidence(self, ai_app) -> None:
        auth = AuthConfig(
            method="header", header_value="Bearer SUPERSECRET-TOKEN-1234567"
        )
        with local_client(ai_app[1]) as client:
            client.target.auth = auth
            client._auth_headers = auth.as_headers()
            result, _ = run_ai(client, **BOTH)
        blob = json.dumps(
            [f.verification.model_dump(mode="json") for f in result.findings]
        )
        assert "SUPERSECRET" not in blob
        assert "ai_unauthenticated_inference" not in classes(result.findings)
