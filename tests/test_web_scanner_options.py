import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from haris.models.scan_config_template import ScanConfigTemplate

from .test_web_env import WebEnv, stub_scan_runner
from .web_helpers import TARGET_URL


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[WebEnv]:
    monkeypatch.delenv("HARIS_ALLOW_PRIVATE_TARGETS", raising=False)
    with pytest.MonkeyPatch.context() as patch:
        stub_scan_runner(patch)
        yield WebEnv(tmp_path)


def _detail(response: Any) -> str:
    body = response.json()
    detail = body["detail"]
    return detail if isinstance(detail, str) else json.dumps(detail)


def test_h3_web_strips_active_flags_and_rejects_urls_and_redirect_flags(
    env: WebEnv,
) -> None:
    alice = env.browser(env.alice)
    cases = [
        {"wapiti": {"external_endpoint": "http://10.0.0.5/"}},
        {"nuclei": {"extra_args": ["-fr"]}},
        {"nikto": {"extra_args": ["-followredirects"]}},
        {"nuclei": {"not_a_real_option": True}},
    ]
    for options in cases:
        response = alice.post(
            "/api/v1/scan-templates",
            json={"name": "bad", "scanner_options": options},
            headers=alice.csrf_headers,
        )
        assert response.status_code == 422
        assert "10.0.0.5" not in _detail(response)

    saved = alice.post(
        "/api/v1/scan-templates",
        json={
            "name": "flags",
            "scanner_options": {
                "ai": {"active": True},
                "ai_security": {
                    "active": True,
                    "authorised": True,
                    "max_prompts": 3,
                },
            },
        },
        headers=alice.csrf_headers,
    )
    assert saved.status_code == 201, saved.text
    options = saved.json()["scanner_options"]
    assert "ai" not in options
    assert options["ai_security"] == {"max_prompts": 3}
    dumped = json.dumps(options)
    assert "active" not in dumped
    assert "authorised" not in dumped


def test_h3_scan_start_rechecks_stored_options(env: WebEnv) -> None:
    template = ScanConfigTemplate(
        name="stored",
        scanner_options={"wapiti": {"external_endpoint": "http://10.0.0.5/"}},
    )
    env.state.store.save_scan_config_template(template, owner_user_id=env.alice.user_id)
    alice = env.browser(env.alice)
    response = alice.post(
        "/api/v1/scans",
        data={"target_url": TARGET_URL, "template_id": template.template_id},
        headers=alice.csrf_headers,
    )
    assert response.status_code == 422
    assert "10.0.0.5" not in _detail(response)

    flags = ScanConfigTemplate(
        name="stored-flags",
        scanner_options={
            "ai_security": {"active": True, "authorised": True, "max_prompts": 3}
        },
    )
    env.state.store.save_scan_config_template(flags, owner_user_id=env.alice.user_id)
    started = alice.post(
        "/api/v1/scans",
        data={"target_url": TARGET_URL, "template_id": flags.template_id},
        headers=alice.csrf_headers,
    )
    assert started.status_code == 202, started.text
    job = env.state.store.jobs.get(started.json()["scan_id"])
    assert job is not None
    stored = job.params["scanner_options"]
    assert stored["ai_security"] == {"max_prompts": 3}
    dumped = json.dumps(stored)
    assert "active" not in dumped
    assert "authorised" not in dumped


def test_m2_api_rejects_bad_excluded_path(env: WebEnv) -> None:
    alice = env.browser(env.alice)
    template = alice.post(
        "/api/v1/scan-templates",
        json={"name": "paths", "excluded_paths": ["(a+)+"]},
        headers=alice.csrf_headers,
    )
    assert template.status_code == 422
    assert "nested" in _detail(template)
    scan = alice.post(
        "/api/v1/scans",
        data={"target_url": TARGET_URL, "excluded_paths": "(a+)+"},
        headers=alice.csrf_headers,
    )
    assert scan.status_code == 422
    assert "nested" in _detail(scan)
