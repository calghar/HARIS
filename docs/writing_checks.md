# Writing Custom Checks

Custom checks are Python-based security tests that don't require external tools. They use the same `BaseScanner` interface as tool adapters.

## When to Write a Custom Check

- The test only requires HTTP requests (use `requests`)
- The test only requires TLS inspection (use Python's `ssl`)
- No external CLI tool is needed
- You want the check to run without any system-level dependencies

## Step-by-Step Guide

### 1. Create the check file

Create a new file in `src/checks/`, for example `src/checks/cors_check.py`:

```python
from __future__ import annotations

from typing import Any

import requests

from ..core.finding import Confidence, Finding, Severity
from ..core.scanner import BaseScanner, ScannerResult
from ..core.target import Target


class CORSCheckScanner(BaseScanner):
    name = "cors_check"
    version = "1.0.0"
    description = "Detailed CORS policy analysis"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 15)

    def scan(self, target: Target) -> ScannerResult:
        result = ScannerResult(scanner_name=self.name)

        try:
            resp = requests.get(
                target.base_url,
                headers={"Origin": "https://evil.example.com"},
                timeout=self.options["timeout"],
            )
        except requests.RequestException as exc:
            result.errors.append(str(exc))
            return result

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            result.findings.append(Finding(
                title="Wildcard CORS policy",
                description="ACAO is set to *",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                url=target.base_url,
                scanner=self.name,
                tags=["cors_misconfiguration"],
            ))

        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []  # Findings created inline
```

### 2. Register the check

In `src/checks/__init__.py`:

```python
from .cors_check import CORSCheckScanner
```

In `scripts/run_scan.py`, add to `CUSTOM_CHECK_REGISTRY`:

```python
CUSTOM_CHECK_REGISTRY["cors_check"] = CORSCheckScanner
```

### 3. Add OWASP mapping tags

Use tags from `src/core/owasp.py` `OWASP_MAPPINGS` keys to enable auto-mapping:

```python
tags=["cors_misconfiguration"]  # Maps to A01: Broken Access Control
```

### 4. Write tests

Create `tests/test_cors_check.py` with mocked HTTP responses:

```python
from unittest.mock import patch, MagicMock
from src.checks.cors_check import CORSCheckScanner
from src.core.target import Target

def test_wildcard_cors():
    mock_resp = MagicMock()
    mock_resp.headers = {"Access-Control-Allow-Origin": "*"}

    with patch("src.checks.cors_check.requests.get", return_value=mock_resp):
        scanner = CORSCheckScanner()
        target = Target(base_url="https://example.com")
        result = scanner.scan(target)
        assert len(result.findings) == 1
```

### 5. Add to configuration

In `config/default_config.yaml`:

```yaml
scanners:
  - name: cors_check
    enabled: true
    options:
      timeout: 15
```

## Best Practices

- Always set `scanner=self.name` on findings
- Use OWASP tag keywords for automatic category mapping
- Include `remediation` text on every finding
- Never store sensitive response data in findings
- Respect `target.scope.is_url_in_scope()` for any URL you probe
- Use timeouts on all network operations
