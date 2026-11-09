import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from ..ai_security.adapters import (
    SKIP_INACTIVE,
    SKIP_NO_ENDPOINT,
    chat_body,
    chat_endpoint,
    selection,
    skipped,
    tool_config,
    tool_finding,
    write_private,
)
from ..ai_security.discovery import Endpoint
from ..ai_security.options import active_enabled
from ..ai_security.probes import load_probes
from ..core.decorators import handle_scanner_errors, register_scanner
from ..models import Finding, ScanContext, ScannerResult, Target
from .base import ExternalToolScanner

logger = logging.getLogger(__name__)

TOOL = "garak"
REPORT_PREFIX = "garak"
REPORT_NAME = f"{REPORT_PREFIX}.report.jsonl"
INPUT_PLACEHOLDER = "$INPUT"
RESPONSE_FIELD = "$.choices[0].message.content"


def _eval_entries(raw: str) -> list[dict[str, Any]]:
    """The report's ``eval`` entries; malformed lines are skipped."""
    entries: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Skipping a malformed garak report line")
            continue
        if isinstance(entry, dict) and entry.get("entry_type") == "eval":
            entries.append(entry)
    return entries


@register_scanner
class GarakScanner(ExternalToolScanner):
    """Runs garak's injection and leakage probes against a discovered chat route.

    Options: ``timeout`` (seconds, default 900), ``probes`` (allow-listed names),
    ``max_prompts``, ``max_tokens_per_prompt``, ``extra_args`` (allow-listed flags).
    Runs only with ``active`` and ``authorised``.
    """

    name = TOOL
    version = "0.17"
    description = "LLM vulnerability probes (prompt injection, leakage) via garak"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 900)
        self.options.setdefault("extra_args", [])

    @handle_scanner_errors
    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        if not active_enabled(self.options):
            return skipped(self.name, SKIP_INACTIVE)
        if not self._check_tool_available(TOOL):
            return ScannerResult(
                scanner_name=self.name,
                errors=["garak is not installed or not on PATH"],
            )
        endpoint = chat_endpoint(target, context)
        if endpoint is None:
            return skipped(self.name, SKIP_NO_ENDPOINT)
        self._begin(target)

        timeout = self.options["timeout"]
        with tempfile.TemporaryDirectory() as tmpdir:
            work = Path(tmpdir)
            cmd = self._build_command(target, endpoint, work)
            run = self._run_to_file(cmd, work / REPORT_NAME, timeout)

        evals = "\n".join(json.dumps(e) for e in _eval_entries(run.raw))
        result = ScannerResult(scanner_name=self.name, raw_output=self._redact(evals))
        result.findings = self.parse_results(run.raw, endpoint.chat_url)
        if run.timed_out:
            result.errors.append(self._timeout_error(timeout))
        elif run.returncode != 0 and not run.raw:
            result.errors.append(
                f"garak exited with code {run.returncode}: "
                f"{self._redact(run.stderr)[:500]}"
            )
        return result

    def parse_results(self, raw_output: str, url: str = "") -> list[Finding]:
        """One finding per eval entry with fails."""
        findings: list[Finding] = []
        for entry in _eval_entries(raw_output):
            fails, total = entry.get("fails", 0), entry.get("total_evaluated", 0)
            if not (isinstance(fails, int) and isinstance(total, int)):
                continue
            if fails <= 0 or total <= 0:
                continue
            probe = self._redact(str(entry.get("probe", "")))
            detector = self._redact(str(entry.get("detector", "")))
            findings.append(
                tool_finding(
                    TOOL,
                    probe.split(".")[0],
                    url=url,
                    label=probe,
                    fails=fails,
                    total=total,
                    parameter=f"{probe}:{detector}",
                    evidence=f"detector {detector}: {fails} of {total} attempts failed",
                    raw_data={
                        "probe": probe,
                        "detector": detector,
                        "fails": fails,
                        "total": total,
                    },
                )
            )
        return findings

    def _build_command(
        self, target: Target, endpoint: Endpoint, work: Path
    ) -> list[str]:
        """Write the generator and run configs; credentials stay in the 0600 file."""
        limits = load_probes().ai
        max_prompts = int(self.options.get("max_prompts", limits.max_prompts))
        max_tokens = int(
            self.options.get("max_tokens_per_prompt", limits.max_tokens_per_prompt)
        )
        probes = selection(TOOL, self.options.get("probes"))
        rest = {
            "rest": {
                "RestGenerator": {
                    "name": TOOL,
                    "uri": endpoint.chat_url,
                    "method": "post",
                    "headers": {
                        "Content-Type": "application/json",
                        **target.auth.as_headers(),
                    },
                    "req_template_json_object": chat_body(
                        endpoint, INPUT_PLACEHOLDER, max_tokens
                    ),
                    "response_json": True,
                    "response_json_field": RESPONSE_FIELD,
                    "request_timeout": tool_config(TOOL).request_timeout,
                }
            }
        }
        run = {
            "run": {"generations": 1, "soft_probe_prompt_cap": max_prompts},
            "reporting": {"report_dir": str(work)},
        }
        write_private(work / "rest.json", json.dumps(rest))
        write_private(work / "run.json", json.dumps(run))
        return [
            TOOL,
            "--target_type",
            "rest",
            "-G",
            str(work / "rest.json"),
            "--config",
            str(work / "run.json"),
            "--spec",
            ",".join(f"probes.{p}" for p in probes),
            "--report_prefix",
            str(work / REPORT_PREFIX),
            "--parallel_attempts",
            "1",
            *self._extra_args(),
        ]
