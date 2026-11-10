import logging
import re
from pathlib import Path

import pytest

import haris
from haris.config.loader import load_config
from haris.models.target import Scope
from haris.scanners.wapiti_exclude import wapiti_exclude_urls

from .test_web_env import WebEnv

DEFAULT_CONFIG = Path(haris.__file__).parent / "resources/config/default_config.yaml"
LABEL = re.compile(r'<label for="excluded_paths">(.*?)</label>', re.DOTALL)
RULE = "one per line, plain path or a trailing .*"
ORIGIN = "http://127.0.0.1:9"
PAGES = ("/scan/new", "/templates/new")


@pytest.fixture
def form_pages(tmp_path: Path) -> dict[str, str]:
    env = WebEnv(tmp_path)
    client = env.browser(env.admin)
    rendered: dict[str, str] = {}
    for path in PAGES:
        response = client.get(path)
        assert response.status_code == 200, path
        rendered[path] = response.text
    return rendered


def test_excluded_path_labels_state_the_shared_rule(form_pages: dict[str, str]) -> None:
    for path, html in form_pages.items():
        match = LABEL.search(html)
        assert match, path
        label = match.group(1)
        assert "regex supported" not in label
        assert RULE in label


def test_default_excluded_paths_suit_scope_and_wapiti(
    caplog: pytest.LogCaptureFixture,
) -> None:
    excluded = load_config(DEFAULT_CONFIG).target.scope.excluded_paths
    with caplog.at_level(logging.WARNING):
        urls = wapiti_exclude_urls(ORIGIN, excluded)
    assert urls == [f"{ORIGIN}/logout", f"{ORIGIN}/api/admin/*"]
    assert [r for r in caplog.records if "cannot take a regex" in r.getMessage()] == []
    scope = Scope(allowed_domains=["example.com"], excluded_paths=excluded)
    assert not scope.is_url_in_scope("https://example.com/logout")
    assert not scope.is_url_in_scope("https://example.com/logout.php")
    assert not scope.is_url_in_scope("https://example.com/api/admin/users")
    assert scope.is_url_in_scope("https://example.com/api/admin")
    assert scope.is_url_in_scope("https://example.com/api/public")
