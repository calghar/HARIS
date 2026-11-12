import importlib.util
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import litellm
import pytest
import yaml

from haris.llm.litellm_backend import LLMConfigError

from .test_web_env import Browser, WebEnv, stub_scan_runner

BEDROCK = "bedrock/us.anthropic.claude-sonnet-5"
GATEWAY_BASE = "https://user:pw@gw.internal:4000/v1?x=1"
KEY = "sk-test-123"
LEGACY = ["anthropic", "openai", "ollama", "bedrock"]
TARGET = "https://a.example.com"


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WebEnv:
    stub_scan_runner(monkeypatch)

    def refuse(**_kwargs: Any) -> None:
        pytest.fail("a model request was sent")

    monkeypatch.setattr(litellm, "completion", refuse)
    return WebEnv(tmp_path)


@pytest.fixture()
def configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    def apply(
        model: str = "",
        api_base: str = "",
        api_key_env: str = "GW_KEY",
        enrichment_enabled: bool = False,
    ) -> None:
        llm = {
            "backend": "litellm",
            "model": model,
            "api_base": api_base,
            "api_key_env": api_key_env,
            "enrichment_enabled": enrichment_enabled,
        }
        path = tmp_path / "haris.yaml"
        path.write_text(yaml.safe_dump({"llm": llm}))
        monkeypatch.setenv("HARIS_CONFIG", str(path))

    return apply


def post(client: Browser, path: str, body: dict[str, Any]) -> Any:
    return client.post(path, json=body, headers=client.csrf_headers)


def names_litellm_and_model(response: Any) -> None:
    detail = response.json()["detail"].lower()
    assert "litellm" in detail
    assert "llm.model" in detail


class TestEndpointDisplay:
    def test_settings_shows_scheme_and_host_only(
        self, env: WebEnv, configure: Callable[..., None]
    ) -> None:
        configure(model=BEDROCK, api_base=GATEWAY_BASE)
        page = env.browser(env.admin).get("/settings")
        assert page.status_code == 200
        assert "https://gw.internal:4000" in page.text
        assert BEDROCK in page.text
        for secret in ("user:pw", "pw@", "x=1", "gw.internal:4000/v1"):
            assert secret not in page.text, secret
        assert 'name="api_key"' not in page.text
        assert 'name="api_base"' not in page.text

    def test_settings_shows_the_litellm_backend_without_config_values(
        self, env: WebEnv, configure: Callable[..., None]
    ) -> None:
        configure()
        page = env.browser(env.admin).get("/settings")
        assert re.search(r"Backend</td><td>litellm</td>", page.text)
        assert "anthropic" not in page.text.lower()

    @pytest.mark.parametrize(
        ("api_base", "shown"),
        [
            (GATEWAY_BASE, "https://gw.internal:4000"),
            ("http://[::1]:8080/path", "http://[::1]:8080"),
            ("https://gw.internal", "https://gw.internal"),
            ("", ""),
            ("gw.internal:4000", ""),
        ],
    )
    def test_backends_endpoint_is_scheme_host_port(
        self,
        env: WebEnv,
        configure: Callable[..., None],
        api_base: str,
        shown: str,
    ) -> None:
        configure(model=BEDROCK, api_base=api_base)
        entry = env.browser(env.alice).get("/api/v1/llm/backends").json()["backends"][0]
        assert entry["endpoint"] == shown
        assert entry["model"] == BEDROCK
        assert "@" not in entry["endpoint"]


class TestAvailability:
    @pytest.mark.parametrize(
        ("installed", "model", "available"),
        [
            (False, BEDROCK, False),
            (True, "", False),
            (True, BEDROCK, True),
        ],
        ids=["not-installed", "blank-model", "installed-valid-model"],
    )
    def test_litellm_availability(
        self,
        env: WebEnv,
        configure: Callable[..., None],
        monkeypatch: pytest.MonkeyPatch,
        installed: bool,
        model: str,
        available: bool,
    ) -> None:
        configure(model=model)
        real_find_spec = importlib.util.find_spec

        def find_spec(name: str, *args: Any) -> Any:
            return (
                None
                if name == "litellm" and not installed
                else real_find_spec(name, *args)
            )

        monkeypatch.setattr(importlib.util, "find_spec", find_spec)
        body = env.browser(env.alice).get("/api/v1/llm/backends").json()
        assert [b["name"] for b in body["backends"]] == ["litellm"]
        entry = body["backends"][0]
        assert entry["available"] is available
        assert bool(entry["reason"]) is not available


class TestLegacyBackendName:
    @pytest.mark.parametrize("name", LEGACY)
    @pytest.mark.parametrize("target", ["chat", "scan-form", "template"])
    def test_legacy_name_is_a_400_naming_litellm_and_llm_model(
        self, env: WebEnv, configure: Callable[..., None], name: str, target: str
    ) -> None:
        configure(model=BEDROCK)
        alice = env.browser(env.alice)
        if target == "chat":
            scan = env.add_scan(env.alice)
            response = post(
                alice,
                "/api/v1/llm/chat",
                {"scan_id": scan, "question": "q", "backend": name},
            )
        elif target == "scan-form":
            response = alice.post(
                "/api/v1/scans",
                data={"target_url": TARGET, "llm_backend": name},
                headers=alice.csrf_headers,
            )
        else:
            response = post(
                alice, "/api/v1/scan-templates", {"name": "t", "llm_backend": name}
            )
        assert response.status_code == 400, response.text
        names_litellm_and_model(response)

    def test_blank_and_litellm_stay_allowed_in_forms(
        self, env: WebEnv, configure: Callable[..., None]
    ) -> None:
        configure()
        alice = env.browser(env.alice)
        for backend in ("", "litellm"):
            started = alice.post(
                "/api/v1/scans",
                data={"target_url": TARGET, "llm_backend": backend},
                headers=alice.csrf_headers,
            )
            assert started.status_code == 202, started.text
            made = post(
                alice, "/api/v1/scan-templates", {"name": "t", "llm_backend": backend}
            )
            assert made.status_code == 201, made.text

    def test_template_update_with_legacy_name_is_a_400(
        self, env: WebEnv, configure: Callable[..., None]
    ) -> None:
        configure(model=BEDROCK)
        alice = env.browser(env.alice)
        template = env.add_template(env.alice)
        response = alice.put(
            f"/api/v1/scan-templates/{template}",
            json={"llm_backend": "anthropic"},
            headers=alice.csrf_headers,
        )
        assert response.status_code == 400

    def test_saved_template_with_a_leftover_name_gives_a_400_at_scan_start(
        self, env: WebEnv, configure: Callable[..., None]
    ) -> None:
        configure(model=BEDROCK)
        template = env.add_template(env.alice)
        env.state.store.save_scan_config_template(
            env.state.store.get_scan_config_template(template).model_copy(  # type: ignore[union-attr]  # just saved
                update={"llm_enrichment": True, "llm_backend": "anthropic"}
            ),
            owner_user_id=env.alice.user_id,
        )
        alice = env.browser(env.alice)
        response = alice.post(
            "/api/v1/scans",
            data={"target_url": TARGET, "template_id": template},
            headers=alice.csrf_headers,
        )
        assert response.status_code == 400
        names_litellm_and_model(response)


class TestEnrichmentAtSubmission:
    @pytest.mark.parametrize("model", ["", "claude-sonnet-5"])
    def test_blank_or_invalid_model_is_a_400_before_the_job_is_queued(
        self, env: WebEnv, configure: Callable[..., None], model: str
    ) -> None:
        configure(model=model)
        alice = env.browser(env.alice)
        before = len(env.state.store.list_sessions())
        response = alice.post(
            "/api/v1/scans",
            data={"target_url": TARGET, "llm_enrich": "on"},
            headers=alice.csrf_headers,
        )
        assert response.status_code == 400, response.text
        names_litellm_and_model(response)
        assert len(env.state.store.list_sessions()) == before

    def test_enrichment_enabled_in_config_is_checked_too(
        self, env: WebEnv, configure: Callable[..., None]
    ) -> None:
        configure(model="", enrichment_enabled=True)
        alice = env.browser(env.alice)
        response = alice.post(
            "/api/v1/scans", data={"target_url": TARGET}, headers=alice.csrf_headers
        )
        assert response.status_code == 400

    def test_valid_model_is_accepted(
        self, env: WebEnv, configure: Callable[..., None]
    ) -> None:
        configure(model=BEDROCK)
        alice = env.browser(env.alice)
        response = alice.post(
            "/api/v1/scans",
            data={"target_url": TARGET, "llm_enrich": "on", "llm_backend": "litellm"},
            headers=alice.csrf_headers,
        )
        assert response.status_code == 202, response.text

    def test_blank_model_without_enrichment_still_starts(
        self, env: WebEnv, configure: Callable[..., None]
    ) -> None:
        configure(model="")
        alice = env.browser(env.alice)
        response = alice.post(
            "/api/v1/scans",
            data={"target_url": TARGET, "llm_backend": "litellm"},
            headers=alice.csrf_headers,
        )
        assert response.status_code == 202, response.text


class TestSecretInAnError:
    def test_provider_error_with_the_key_reaches_neither_log_nor_response(
        self,
        env: WebEnv,
        configure: Callable[..., None],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        configure(model="openai/alias", api_base="https://gw.internal:4000")
        monkeypatch.setenv("GW_KEY", KEY)

        def failing(**_kwargs: Any) -> None:
            raise RuntimeError(f"upstream rejected key {KEY}")

        monkeypatch.setattr(litellm, "completion", failing)
        scan = env.add_scan(env.alice)
        with caplog.at_level(logging.DEBUG):
            response = post(
                env.browser(env.alice),
                "/api/v1/llm/ask",
                {"scan_id": scan, "question": "q"},
            )
        assert response.status_code == 500
        assert KEY not in response.text
        assert KEY not in caplog.text
        assert "[REDACTED]" in caplog.text

    def test_config_error_text_with_the_key_is_scrubbed_in_the_400_body(
        self,
        env: WebEnv,
        configure: Callable[..., None],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        configure(model=BEDROCK)
        monkeypatch.setenv("GW_KEY", KEY)

        def failing(*_args: Any, **_kwargs: Any) -> None:
            raise LLMConfigError(f"llm.model rejected near {KEY}")

        monkeypatch.setattr("haris.web.llm_support.create_backend_from_config", failing)
        scan = env.add_scan(env.alice)
        with caplog.at_level(logging.DEBUG):
            response = post(
                env.browser(env.alice),
                "/api/v1/llm/ask",
                {"scan_id": scan, "question": "q"},
            )
        assert response.status_code == 400
        assert KEY not in response.text
        assert KEY not in caplog.text
        assert "[REDACTED]" in response.text
