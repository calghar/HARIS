"""Tests for the Target and Scope models."""


from src.models import AuthConfig, Scope, Target


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
        assert not scope.is_url_in_scope(
            "https://example.com/api/v2/internal"
        )
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
