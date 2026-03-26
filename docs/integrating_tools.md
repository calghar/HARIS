# Integrating External Tools

External tool adapters wrap CLI-based security tools, executing them as subprocesses and parsing their output into the unified Finding model.

## Architecture Pattern

```txt
BaseScanner
    |
    +-- _build_command(target, output_path) -> list[str]
    |       Constructs the CLI command with appropriate flags
    |
    +-- scan(target, context=None) -> ScannerResult
    |       1. Check tool availability
    |       2. Read ScanContext for cross-scanner intelligence (optional)
    |       3. Create temp directory for output
    |       4. Build and run command
    |       5. Read raw output
    |       6. Parse into findings
    |
    +-- parse_results(raw_output) -> list[Finding]
            Converts tool-specific format (JSON/XML) to Finding objects
```

The `scan()` method receives an optional `ScanContext` parameter containing technologies, URLs, ports, and headers detected by earlier scanners. Adapters can use this to make smarter decisions (e.g. Nuclei selects tech-specific templates).

## Step-by-Step Guide

### 1. Research the tool

Before integrating, understand:

- What output formats does it support? (JSON preferred, XML acceptable)
- What CLI flags control scope, rate limiting, output?
- What vulnerability categories does it detect?
- How do its severity levels map to ours?

### 2. Create the adapter

Create `src/scanners/my_tool_scanner.py`:

```python
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from ..core.finding import Confidence, Finding, Severity
from ..core.scanner import BaseScanner, ScannerResult
from ..core.target import Target


# Map tool severity -> internal severity
SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# Map tool categories -> OWASP tags
CATEGORY_TAGS = {
    "sql-injection": ["sql_injection"],
    "xss": ["xss"],
}


class MyToolScanner(BaseScanner):
    name = "my_tool"
    version = "1.0"
    description = "What this tool does"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 300)

    def scan(self, target: Target) -> ScannerResult:
        # 1. Check tool availability
        if not self._check_tool_available("my-tool"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["my-tool is not installed"],
            )

        # 2. Create temp output file
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "results.json"

            # 3. Build and run
            cmd = self._build_command(target, str(output_file))
            returncode, stdout, stderr = self._run_command(
                cmd, timeout=self.options["timeout"]
            )

            # 4. Read output
            raw = ""
            if output_file.exists():
                raw = output_file.read_text()

            result = ScannerResult(scanner_name=self.name, raw_output=raw)

            if returncode != 0 and not raw:
                result.errors.append(f"Exited {returncode}: {stderr[:500]}")

            # 5. Parse findings
            if raw:
                result.findings = self.parse_results(raw)

            return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        findings = []
        data = json.loads(raw_output)

        for item in data.get("results", []):
            severity = SEVERITY_MAP.get(item["severity"], Severity.INFO)
            tags = CATEGORY_TAGS.get(item["category"], [])

            findings.append(Finding(
                title=item["name"],
                description=item["description"],
                severity=severity,
                confidence=Confidence.FIRM,
                url=item.get("url", ""),
                scanner=self.name,
                tags=tags,
            ))

        return findings

    def _build_command(self, target: Target, output_path: str) -> list[str]:
        return [
            "my-tool",
            "--target", target.base_url,
            "--output", output_path,
            "--format", "json",
        ]
```

### 3. Register the scanner

In `src/scanners/__init__.py`:

```python
from .my_tool_scanner import MyToolScanner
SCANNER_REGISTRY["my_tool"] = MyToolScanner
```

### 4. Map to OWASP categories

Add entries to `CATEGORY_TAGS` in your scanner that use keyword keys from `src/core/owasp.py` `OWASP_MAPPINGS`.

### 5. Document the integration

Add a docstring to the scanner module explaining:

- What the tool does
- How to install it
- What vulnerability categories it covers
- Any known limitations

## Existing Integrations

### Wapiti (`src/scanners/wapiti_scanner.py`)

- **Focus**: Web application vulnerability scanning (SQLi, XSS, injection, SSRF)
- **Output**: JSON
- **Key flags**: `--scope`, `--timeout`, `--max-scan-time`, `--module`

### SSLyze (`src/scanners/sslyze_scanner.py`)

- **Focus**: TLS/SSL configuration analysis
- **Output**: JSON
- **Checks**: Protocol support, cipher suites, certificate validity, Heartbleed, ROBOT

### Nmap (`src/scanners/nmap_scanner.py`)

- **Focus**: Port scanning, service detection, reconnaissance
- **Output**: XML
- **Key flags**: `-sV` (version detection), `-p` (ports), `--open`

### Nuclei (`src/scanners/nuclei_scanner.py`)

- **Focus**: CVE detection, default credentials, exposed panels, technology fingerprinting
- **Output**: JSONL (one JSON object per line)
- **Strategy**: Multi-phase scanning
  - **Phase 1**: `http/technologies` templates for fingerprinting (detects CMS, WAF, frameworks)
  - **Phase 2a**: Broad scan across 8 `DEFAULT_TEMPLATE_DIRS` (CVEs, exposures, panels, vulnerabilities, default-logins, takeovers, misconfigurations, DAST)
  - **Phase 2b**: Tech-targeted scan using `TECH_TAG_MAP` and `TECH_WORKFLOW_MAP` based on `ScanContext`
- **Key flags**: `-jsonl`, `-duc`, `-silent`, `-fhr`, `-retries 2`, `-nmhe`, `-tls-impersonate`
- **Context-aware**: Uses `ScanContext.detected_technologies` to select targeted Nuclei tags and workflows

## Testing Adapters

Use mock output files to test parsing without running the actual tool:

```python
from pathlib import Path
from src.scanners.my_tool_scanner import MyToolScanner

def test_parse_results():
    mock_output = Path("tests/fixtures/my_tool_output.json").read_text()
    scanner = MyToolScanner()
    findings = scanner.parse_results(mock_output)
    assert len(findings) > 0
    assert findings[0].severity is not None
```
