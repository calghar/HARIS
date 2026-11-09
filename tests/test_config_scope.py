import pytest

from haris.config.loader import CONFIG_ENV_VAR, load_config


@pytest.mark.parametrize("url", ["http://127.0.0.1:18081", "https://app.test.example"])
def test_url_override_scopes_to_the_target_host(url, monkeypatch):
    """`haris --url X` with the packaged config must keep X in scope."""
    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)
    monkeypatch.chdir("/")
    config = load_config(overrides={"target": {"url": url}})
    host = url.split("://")[1].split(":")[0]
    assert config.target.scope.allowed_domains == [host]
    assert config.target.scope.is_url_in_scope(f"{url}/robots.txt")
