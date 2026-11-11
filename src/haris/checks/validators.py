import json
import re
from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from ..net import ScopedResponse

DS_STORE_MAGIC = bytes.fromhex("0000000142756431")
SPAN_LIMIT = 80


class ValidatorResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    passed: bool
    reason: str
    span: str = ""


class ContentValidator(Protocol):
    name: str

    def validate(self, resp: ScopedResponse) -> ValidatorResult: ...


def _result(passed: bool, reason: str, span: str = "") -> ValidatorResult:
    return ValidatorResult(passed=passed, reason=reason, span=span[:SPAN_LIMIT])


def _json_body(resp: ScopedResponse) -> Any:
    try:
        return json.loads(resp.text)
    except ValueError:
        return None


class EnvFile:
    name = "env_file"
    _LINE = re.compile(r"^[A-Z_][A-Z0-9_]*=", re.MULTILINE)
    MIN_LINES = 2

    def validate(self, resp: ScopedResponse) -> ValidatorResult:
        text = resp.text
        if text.lstrip().startswith("<"):
            return _result(False, "body is markup, not KEY=VALUE lines")
        keys = self._LINE.findall(text)
        if len(keys) < self.MIN_LINES:
            return _result(False, f"fewer than {self.MIN_LINES} KEY=VALUE lines")
        return _result(True, "KEY=VALUE lines", keys[0])  # key only, never the value


class GitConfig:
    name = "git_config"

    def validate(self, resp: ScopedResponse) -> ValidatorResult:
        text = resp.text
        if "[core]" in text and "repositoryformatversion" in text:
            return _result(True, "git config sections", "[core]")
        return _result(False, "no [core] section with repositoryformatversion")


class GitHead:
    name = "git_head"
    _REF = re.compile(r"^ref: refs/\S*", re.MULTILINE)

    def validate(self, resp: ScopedResponse) -> ValidatorResult:
        match = self._REF.match(resp.text)
        if match:
            return _result(True, "git HEAD ref", match.group(0))
        return _result(False, "body does not start with 'ref: refs/'")


class DsStore:
    name = "ds_store"

    def validate(self, resp: ScopedResponse) -> ValidatorResult:
        if resp.content.startswith(DS_STORE_MAGIC):
            return _result(True, "DS_Store magic bytes", "Bud1")
        return _result(False, "no DS_Store magic bytes")


class ContainsAll:
    """Passes when every needle appears in the body."""

    def __init__(self, name: str, *needles: str) -> None:
        self.name = name
        self._needles = needles

    def validate(self, resp: ScopedResponse) -> ValidatorResult:
        text = resp.text
        missing = [n for n in self._needles if n not in text]
        if missing:
            return _result(False, f"missing {missing[0]!r}")
        return _result(True, "marker text present", self._needles[0])


class Matches:
    """Passes when the pattern is found in the body."""

    def __init__(self, name: str, pattern: str) -> None:
        self.name = name
        self._pattern = re.compile(pattern, re.MULTILINE)

    def validate(self, resp: ScopedResponse) -> ValidatorResult:
        match = self._pattern.search(resp.text)
        if match:
            return _result(True, "pattern matched", match.group(0).strip())
        return _result(False, f"pattern {self._pattern.pattern!r} not found")


class JsonKey:
    """Passes for a JSON object that has at least one of *keys*."""

    def __init__(self, name: str, *keys: str) -> None:
        self.name = name
        self._keys = keys

    def validate(self, resp: ScopedResponse) -> ValidatorResult:
        body = _json_body(resp)
        if not isinstance(body, dict):
            return _result(False, "body is not a JSON object")
        for key in self._keys:
            if key in body:
                return _result(True, "JSON key present", key)
        return _result(False, f"JSON object lacks {' or '.join(self._keys)}")


_OPENAPI = JsonKey("openapi_document", "openapi", "swagger")
_SWAGGER_UI = Matches("swagger_ui", r"(?i)swagger-ui")
_VERSION_STRING = Matches("version_string", r"\d+\.\d+")

VALIDATORS: dict[str, ContentValidator] = {
    "/.env": EnvFile(),
    "/.git/config": GitConfig(),
    "/.git/HEAD": GitHead(),
    "/server-status": ContainsAll("apache_status", "Apache Server Status"),
    "/phpinfo.php": ContainsAll("phpinfo", "PHP Version", "phpinfo()"),
    "/.DS_Store": DsStore(),
    "/openapi.json": _OPENAPI,
    "/swagger.json": _OPENAPI,
    "/actuator/env": JsonKey("actuator_env", "propertySources"),
    "/api-docs": _OPENAPI,
    "/v2/api-docs": _OPENAPI,
    "/v3/api-docs": _OPENAPI,
    "/api/openapi.json": _OPENAPI,
    "/swagger/v1/swagger.json": _OPENAPI,
    "/actuator": JsonKey("actuator_index", "_links"),
    "/health": JsonKey("health", "status"),
    "/metrics": Matches("prometheus_metrics", r"^# (?:HELP|TYPE) "),
    "/swagger-ui": _SWAGGER_UI,
    "/swagger-ui.html": _SWAGGER_UI,
    "/version": _VERSION_STRING,
    "/api/version": _VERSION_STRING,
    "/app/version": _VERSION_STRING,
    "/robots.txt": Matches(
        "robots_txt", r"(?im)^\s*(?:user-agent|disallow|allow|sitemap)\s*:"
    ),
    "/sitemap.xml": Matches("sitemap_xml", r"<(?:urlset|sitemapindex)\b"),
    "/.well-known/security.txt": Matches("security_txt", r"(?im)^contact\s*:"),
    "/crossdomain.xml": ContainsAll("crossdomain_xml", "<cross-domain-policy"),
    "/server-info": ContainsAll("apache_info", "Apache Server Information"),
    "/wp-login.php": ContainsAll("wp_login", "user_login"),
    "/phpmyadmin": ContainsAll("phpmyadmin", "phpMyAdmin"),
    "/elmah.axd": ContainsAll("elmah", "Error Log for"),
    "/trace.axd": ContainsAll("aspnet_trace", "Application Trace"),
}


def validator_for(path: str) -> ContentValidator | None:
    """The validator registered for a request path (query string ignored)."""
    return VALIDATORS.get(urlsplit(path).path)
