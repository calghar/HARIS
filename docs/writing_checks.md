# Writing custom checks

A custom check is a `BaseScanner` with `@register_check`. HTTP goes through `ScopedClient`. The runner reads `haris.core.decorators.check_registry`, which the decorator fills when the module is imported.

Registration is that decorator and the import in `src/haris/checks/__init__.py`. The CLI has no `CUSTOM_CHECK_REGISTRY`.

## Example

```python
from haris.checks.requesting import scan_client, try_request
from haris.core.decorators import register_check
from haris.core.scanner import BaseScanner
from haris.models import Finding, ScanContext, ScannerResult, Severity, Target


@register_check
class CORSCheckScanner(BaseScanner):
    name = "cors_check"
    version = "1.0.0"
    description = "CORS policy on the front page"

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        result = ScannerResult(scanner_name=self.name)
        with scan_client(target, context) as client:
            resp = try_request(
                client,
                "GET",
                target.base_url,
                headers={"Origin": "https://evil.example.com"},
            )
        if resp is None:
            result.errors.append("request failed")
            return result
        if resp.headers.get("access-control-allow-origin") == "*":
            result.findings.append(
                Finding(
                    title="Wildcard CORS policy",
                    description="ACAO is *",
                    severity=Severity.MEDIUM,
                    url=target.base_url,
                    scanner=self.name,
                    vuln_class="cors_misconfiguration",
                    tags=["cors_misconfiguration"],
                )
            )
        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []
```

`ScopedResponse.headers` is a `CaseInsensitiveDict`, so the header lookup ignores case.

## Register

Import the class from `src/haris/checks/__init__.py`. A profile runs only the names in `src/haris/core/profiles.py`. Add the name there to include the check in a profile. A run with no profile uses the scanner list in `default_config.yaml`.

## OWASP tag

The finding's canonical class (`CLASS_OWASP` in `src/haris/core/owasp.py`) sets the category first. Without a class entry, a tag that matches a key in `OWASP_MAPPINGS` sets it, then the title. `cors_misconfiguration` maps to A01:2025 Broken Access Control.

Set `vuln_class` to an id in `vuln_classes.yaml`. An unknown class stays `unclassified:`.

## Test

A test calls `scan` with a stand-in for `ScopedClient`. The lint rule bans `requests`, `httpx` and `urllib3` outside `src/haris/net/`.

## Practices

- Set `scanner` to `self.name`.
- Set `remediation` on the finding.
- `ScopedClient` applies scope, the SSRF guard, the rate limit and `max_requests`.
