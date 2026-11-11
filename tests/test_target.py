import re
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from haris.cli import main
from haris.core.exit_codes import EXIT_USAGE
from haris.models import AuthConfig, Scope, Target
from haris.models.target import MAX_EXCLUDED_PATH_CHARS


class TestScope:
    def test_url_in_scope_allowed_domain(self):
        scope = Scope(allowed_domains=["example.com"])
        assert scope.is_url_in_scope("https://example.com/page")
        assert scope.is_url_in_scope("https://sub.example.com/page")

    def test_url_out_of_scope(self):
        scope = Scope(allowed_domains=["example.com"])
        assert not scope.is_url_in_scope("https://evil.com/page")

    def test_excluded_paths(self):
        scope = Scope(
            allowed_domains=["example.com"],
            excluded_paths=["/admin", "/logout"],
        )
        assert scope.is_url_in_scope("https://example.com/page")
        assert not scope.is_url_in_scope("https://example.com/admin")
        assert not scope.is_url_in_scope("https://example.com/logout")

    def test_excluded_path_regex(self):
        scope = Scope(
            allowed_domains=["example.com"],
            excluded_paths=[r"/api/v\d+/internal"],
        )
        assert not scope.is_url_in_scope("https://example.com/api/v2/internal")
        assert scope.is_url_in_scope("https://example.com/api/v2/public")

    def test_empty_allowed_domains_allows_all(self):
        scope = Scope(allowed_domains=[])
        assert scope.is_url_in_scope("https://anything.com/page")

    def test_defaults(self):
        scope = Scope()
        assert scope.rate_limit_rps == 10.0
        assert scope.max_requests == 10_000
        assert scope.max_depth == 5
        assert "GET" in scope.allowed_methods


class TestAuthConfig:
    def test_header_auth(self):
        auth = AuthConfig(
            method="header",
            header_name="Authorization",
            header_value="Bearer tok123",
        )
        headers = auth.as_headers()
        assert headers["Authorization"] == "Bearer tok123"

    def test_cookie_auth(self):
        auth = AuthConfig(
            method="cookie",
            cookie_name="session",
            cookie_value="abc123",
        )
        headers = auth.as_headers()
        assert headers["Cookie"] == "session=abc123"

    def test_no_auth(self):
        auth = AuthConfig(method="none")
        assert auth.as_headers() == {}


class TestTarget:
    def test_url_normalisation(self):
        t = Target(base_url="example.com")
        assert t.base_url == "https://example.com"

    def test_trailing_slash_removed(self):
        t = Target(base_url="https://example.com/")
        assert t.base_url == "https://example.com"

    def test_auto_populate_allowed_domains(self):
        t = Target(base_url="https://example.com")
        assert t.scope.allowed_domains == ["example.com"]

    def test_hostname_property(self):
        t = Target(base_url="https://example.com:8443/path")
        assert t.hostname == "example.com"

    def test_port_property(self):
        t = Target(base_url="https://example.com:8443")
        assert t.port == 8443

    def test_default_port_https(self):
        t = Target(base_url="https://example.com")
        assert t.port == 443

    def test_default_port_http(self):
        t = Target(base_url="http://example.com")
        assert t.port == 80

    def test_scheme_property(self):
        t = Target(base_url="http://example.com")
        assert t.scheme == "http"


_REJECTED_EXCLUDED = [
    "(a+)+",
    "(a*)*",
    "(a+){2}",
    "((a+))+",
    "(a|aa)+$",
    "(a|a)*",
    "(a|b)+",
    "(?:a|aa)+",
]
_ACCEPTED_EXCLUDED = [
    "(ab)+",
    "(?:ab)+",
    "a+",
    "/x[0-9]+",
    "(a+)",
    "/logout",
    "/api/admin/.*",
]
_NON_MATCH = "/" + ("b" * 20_000)
_MATCH_BUDGET_S = 1.0


@pytest.mark.parametrize("pattern", _REJECTED_EXCLUDED)
def test_m2_nested_quantifier_is_rejected(pattern: str) -> None:
    with pytest.raises(ValidationError, match="nested quantifiers"):
        Scope(excluded_paths=[pattern])


@pytest.mark.parametrize("pattern", _ACCEPTED_EXCLUDED)
def test_m2_plain_patterns_are_accepted(pattern: str) -> None:
    assert Scope(excluded_paths=[pattern]).excluded_paths == [pattern]


@pytest.mark.parametrize("pattern", _ACCEPTED_EXCLUDED)
def test_m2_accepted_pattern_finishes_on_a_long_non_match(pattern: str) -> None:
    assert re.search(pattern, _NON_MATCH) is None
    scope = Scope(excluded_paths=[pattern])
    started = time.perf_counter()
    assert scope.is_url_in_scope(f"https://example.com{_NON_MATCH}") is True
    assert time.perf_counter() - started < _MATCH_BUDGET_S


def test_m2_invalid_regex_is_rejected() -> None:
    with pytest.raises(ValidationError, match="not a valid regex"):
        Scope(excluded_paths=["["])


def test_m2_long_pattern_is_rejected() -> None:
    pattern = "a" * (MAX_EXCLUDED_PATH_CHARS + 1)
    with pytest.raises(ValidationError, match="longer than"):
        Scope(excluded_paths=[pattern])


def test_m2_cli_rejects_nested_excluded_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "scan.yaml"
    config.write_text(
        "target:\n  url: https://example.com\n  scope:\n"
        "    excluded_paths:\n      - '(a+)+'\n"
    )
    assert main(["--config", str(config), "--yes"]) == EXIT_USAGE
    assert "nested quantifiers" in capsys.readouterr().err
