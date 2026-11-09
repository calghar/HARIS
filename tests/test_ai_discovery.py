import pytest

from haris.ai_security.body_validators import VALIDATORS
from haris.ai_security.discovery import discover
from haris.ai_security.signatures import load_signatures
from haris.models import VerificationTier

from .ai_support import (
    initialize_result,
    json_reply,
    local_client,
    rpc_reply,
    run_ai,
    scope_with_post,
)
from .checks_support import NOT_FOUND, html, site
from .test_bench_fixtures import serve

EVENT_STREAM: tuple[int, dict[str, str], bytes] = (
    200,
    {"Content-Type": "text/event-stream"},
    b"event: endpoint\ndata: /messages\n\n",
)
SPA_INDEX = html()

# (path, reply, expected signature id or None) — the ai-security.feature matrix.
MATRIX = [
    (
        "/v1/models",
        json_reply({"object": "list", "data": [{"id": "gpt-x"}]}),
        "openai_compatible",
    ),
    ("/v1/models", SPA_INDEX, None),
    ("/api/tags", json_reply({"models": []}), "ollama"),
    ("/info", json_reply({"model_id": "m", "max_input_tokens": 4096}), "tgi"),
    ("/v2", json_reply({"name": "triton", "extensions": []}), "triton"),
    ("/config", json_reply({"version": "4.0", "components": []}), "gradio"),
    ("/system_stats", json_reply({"system": {}, "devices": []}), "comfyui"),
    ("/api/kernels", json_reply([]), "jupyter"),
    ("/mcp", rpc_reply(initialize_result()), "mcp_streamable_http"),
    ("/sse", EVENT_STREAM, "mcp_sse"),
    (
        "/.well-known/oauth-protected-resource",
        json_reply({"resource": "r", "authorization_servers": ["a"]}),
        "oauth_protected_resource",
    ),
    ("/api/tags", json_reply({"error": "not found"}), None),
]


class TestSignatureMatrix:
    @pytest.mark.parametrize(("path", "reply", "expected"), MATRIX)
    def test_validator_matrix(self, path, reply, expected) -> None:
        net = site({path: reply}, scope=scope_with_post())
        found = {e.signature.id for e in discover(net.client, net.client.target)}
        assert found == ({expected} if expected else set())

    def test_every_signature_names_a_registered_validator(self) -> None:
        for sig in load_signatures().signatures:
            assert sig.validator in VALIDATORS

    def test_vllm_is_told_apart_from_openai_compatible(self) -> None:
        reply = json_reply(
            {"object": "list", "data": [{"id": "m", "owned_by": "vllm"}]}
        )
        net = site({"/v1/models": reply}, scope=scope_with_post())
        ids = {e.signature.id for e in discover(net.client, net.client.target)}
        assert ids == {"vllm"}

    def test_soft_404_match_is_refused_even_if_a_validator_would_pass(self) -> None:
        body = json_reply({"object": "list", "data": [{"id": "x"}]})
        net = site(fallback=body, scope=scope_with_post())
        assert discover(net.client, net.client.target) == []

    def test_discovery_sends_no_chat_prompt(self) -> None:
        net = site(
            {"/v1/models": json_reply({"object": "list", "data": [{"id": "m"}]})},
            scope=scope_with_post(),
        )
        discover(net.client, net.client.target)
        bodies = [r.body for r in net.sent if r.method == "POST"]
        assert all("messages" not in str(b or "") for b in bodies)


class TestCatchAll:
    def test_fake_catch_all_yields_nothing(self) -> None:
        net = site(fallback=SPA_INDEX, scope=scope_with_post())
        assert discover(net.client, net.client.target) == []

    def test_spa_catchall_fixture_yields_no_ai_finding(self) -> None:
        for _, url in serve("spa_catchall"):
            with local_client(url) as client:
                result, _ = run_ai(client, active=True, authorised=True)
        assert result.findings == []
        assert result.errors == []


class TestDiscoveryReplay:
    def test_discovery_finding_is_replay_verified_when_it_holds_again(self) -> None:
        net = site({"/api/tags": json_reply({"models": []})}, scope=scope_with_post())
        result, _ = run_ai(net.client)
        found = [f for f in result.findings if f.vuln_class == "ai_endpoint_discovered"]
        assert [f.verification.tier for f in found] == [
            VerificationTier.REPLAY_VERIFIED
        ]

    def test_discovery_finding_is_refuted_when_replay_matches_the_baseline(
        self,
    ) -> None:
        served = iter([json_reply({"models": []})])

        def flaky(_request: object):  # type: ignore[no-untyped-def]
            return next(served, NOT_FOUND)

        net = site({"/api/tags": flaky}, scope=scope_with_post())
        result, _ = run_ai(net.client)
        found = [f for f in result.findings if f.vuln_class == "ai_endpoint_discovered"]
        assert [f.verification.tier for f in found] == [VerificationTier.REFUTED]

    def test_vuln_ai_app_is_discovered_with_chat_url_and_models(self) -> None:
        for _, url in serve("vuln_ai_app"):
            with local_client(url) as client:
                endpoints = discover(client, client.target)
        by_id = {e.signature.id: e for e in endpoints}
        assert set(by_id) == {"openai_compatible", "mcp_streamable_http"}
        assert by_id["openai_compatible"].chat_url == url + "/v1/chat/completions"
        assert by_id["openai_compatible"].models == ("bench-fake-model",)
