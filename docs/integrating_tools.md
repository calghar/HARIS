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

Create `src/haris/scanners/my_tool_scanner.py`:

```python
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from haris.core.scanner import BaseScanner
from haris.models import Confidence, Finding, ScannerResult, Severity, Target


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

            findings.append(
                Finding(
                    title=item["name"],
                    description=item["description"],
                    severity=severity,
                    confidence=Confidence.FIRM,
                    url=item.get("url", ""),
                    scanner=self.name,
                    tags=tags,
                )
            )

        return findings

    def _build_command(self, target: Target, output_path: str) -> list[str]:
        return [
            "my-tool",
            "--target",
            target.base_url,
            "--output",
            output_path,
            "--format",
            "json",
        ]
```

### 3. Register the scanner

Import the class in `src/haris/scanners/__init__.py` and add it to `SCANNER_REGISTRY` under its `name`. `get_scanner` and the scan runner read that dict.

```python
from .my_tool_scanner import MyToolScanner

SCANNER_REGISTRY = {
    # ...
    "my_tool": MyToolScanner,
}
```

### 4. Map to OWASP categories

Add entries to `CATEGORY_TAGS` in your scanner that use keyword keys from `src/haris/core/owasp.py` `OWASP_MAPPINGS`.

### 5. Document the integration

The scanner module docstring names the tool's purpose, the install command, the vulnerability categories and the known limits.

## Existing Integrations

### Wapiti (`src/haris/scanners/wapiti_scanner.py`)

- **Focus**: Web application vulnerability scanning (SQLi, XSS, injection, SSRF)
- **Output**: JSON
- **Key flags**: `--scope`, `--timeout`, `--max-scan-time`, `--module`
- Without both `external_endpoint` and `internal_endpoint` set, the SSRF and XXE modules are skipped and `log4shell` is always skipped. The internal placeholder is the target's base URL and the external placeholder is `http://127.0.0.1:9/`.

### SSLyze (`src/haris/scanners/sslyze_scanner.py`)

- **Focus**: TLS/SSL configuration analysis
- **Output**: JSON
- **Checks**: Protocol support, cipher suites, certificate validity, Heartbleed, ROBOT

### Nmap (`src/haris/scanners/nmap_scanner.py`)

- **Focus**: Port scanning, service detection, reconnaissance
- **Output**: XML
- **Key flags**: `-sV` (version detection), `-p` (ports), `--open`

### ZAP (`src/haris/scanners/zap_scanner.py`)

- **Focus**: Active and passive web scanning through the Automation Framework
- **Output**: `traditional-json` (`site[].alerts[].instances[]`)
- **Invocation**: `<launcher> -cmd -autorun plan.yaml -dir <home> -silent`
- **Launchers on PATH**, in order: `zap.sh`, `zap.bat` (the documented launchers; `zap.exe` ignores these flags), then `zaproxy` and `zap`
- **Plan**: context URL (no `:80` or `:443`), include and exclude regexes from scope, spider, `passiveScan-wait`, `activeScan` with a minute cap, then a report job. Auth headers are a `replacer` rule in the plan file (mode 0600), not command-line arguments.
- **Default**: `enabled: false` in `default_config.yaml`, and absent from every profile. Run it with `--scanners zap`.

### Nuclei (`src/haris/scanners/nuclei_scanner.py`)

- **Focus**: technology-targeted templates plus a baseline of exposure, misconfiguration, vulnerability, takeover and DAST checks
- **Output**: JSONL (one JSON object per line)
- **Argv**: `nuclei_argv.py` holds technology-tag mapping and argv construction; `nuclei_scanner.py` runs the process
- **Strategy**: two groups under one deadline (`phase2_timeout_s`)
  - **Tag group**: templates outside the baseline dirs that carry a selected tag. Selected tags are the `TECH_TAG_MAP` tags for `ScanContext` technologies plus the tags the LLM selector adds (`nuclei_selection.py`); with none, `-as` runs instead. `TECH_WORKFLOW_MAP` workflows run here too.
  - **Baseline group**: the `baseline_template_dirs` of `nuclei.yaml`, run with `-u <base_url>` and no `-list`
  - **URL list**: only the tag group gets `-list`; it holds the base URL plus discovered URLs with the same scheme, host and port
  - **Selector settings** (`nuclei.yaml`): `max_selected_tags`, `deny_tags`, `min_tag_templates`, `max_tag_templates`
  - **Explicit options**: `template_dirs` or `tags` give one run and skip the selector
  - **Note**: every run records `template selection: llm tags <list>` or `template selection: deterministic (<reason>)`
- **Flags on every run**: `-jsonl`, `-or`, `-ot`, `-duc`, `-silent`, `-no-color`, `-system-resolvers`, `-tls-impersonate`, `-fhr`, `-retries` (the `retries` option, default 2), `-mhe` (the `max_host_errors` option), and one rate flag (`-rate-limit` from `rate_limit`, or `-rl` when the scan rate is bound)
- **Context-aware**: Uses `ScanContext.detected_technologies` to select targeted Nuclei tags and workflows

## Testing Adapters

Use mock output files to test parsing without running the actual tool:

```python
from pathlib import Path
from haris.scanners.my_tool_scanner import MyToolScanner


def test_parse_results():
    mock_output = Path("tests/fixtures/my_tool_output.json").read_text()
    scanner = MyToolScanner()
    findings = scanner.parse_results(mock_output)
    assert len(findings) > 0
    assert findings[0].severity is not None
```
