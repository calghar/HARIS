import json
import logging
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from ..ai_security.adapters import (
    SKIP_INACTIVE,
    SKIP_NO_ENDPOINT,
    chat_body,
    chat_endpoint,
    preflight_endpoint,
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
from .base import ExternalToolScanner, ToolRun

logger = logging.getLogger(__name__)

TOOL = "promptfoo"
CONFIG_NAME = "promptfooconfig.yaml"
TESTS_NAME = "redteam.yaml"
RESULTS_NAME = "results.json"
PROMPT_VAR = "{{prompt}}"
RESPONSE_EXPR = "json.choices[0].message.content"
PROVIDER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,99}$")
ERROR_REASON = 2
# promptfoo exits 100 when at least one test fails.
OK_RETURNCODES = (0, 100)


class MalformedOutputError(ValueError):
    pass


def _plugin_id(entry: dict[str, Any]) -> str:
    for holder in (
        entry.get("metadata"),
        (entry.get("testCase") or {}).get("metadata"),
    ):
        if isinstance(holder, dict) and holder.get("pluginId"):
            return str(holder["pluginId"])
    return ""


@register_scanner
class PromptfooScanner(ExternalToolScanner):
    """Runs promptfoo red-team plugins (injection, leakage) against a chat route.

    Options: ``timeout`` (seconds per step, default 900), ``plugins`` (allow-listed),
    ``provider`` (test-generation model; promptfoo's own default if unset),
    ``max_prompts``, ``max_tokens_per_prompt``, ``extra_args`` (allow-listed flags
    for the eval step). Runs only with ``active`` and ``authorised``.
    """

    name = TOOL
    version = "0.125"
    description = "LLM red-team plugins (prompt injection, leakage) via promptfoo"

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
                errors=["promptfoo is not installed or not on PATH"],
            )
        endpoint = chat_endpoint(target, context)
        if endpoint is None:
            return skipped(self.name, SKIP_NO_ENDPOINT)
        blocked = preflight_endpoint(self.name, context, endpoint.chat_url)
        if blocked is not None:
            return blocked
        self._begin(target)

        timeout = self.options["timeout"]
        with tempfile.TemporaryDirectory() as tmpdir:
            work = Path(tmpdir)
            self._write_config(target, endpoint, work)
            generate = self._run_to_file(
                self._generate_command(work), work / TESTS_NAME, timeout
            )
            result = ScannerResult(scanner_name=self.name)
            if generate.timed_out or generate.returncode != 0:
                result.errors.append(
                    self._step_error("test generation", generate, timeout)
                )
                return result
            run = self._run_to_file(
                self._eval_command(work), work / RESULTS_NAME, timeout
            )

        result.raw_output = self._redact(run.raw)
        if run.timed_out:
            result.errors.append(self._timeout_error(timeout))
        elif run.returncode not in OK_RETURNCODES and not run.raw:
            result.errors.append(self._step_error("eval", run, timeout))
        if run.raw:
            try:
                result.findings = self.parse_results(run.raw, endpoint.chat_url)
            except MalformedOutputError as exc:
                result.errors.append(f"promptfoo output could not be parsed: {exc}")
        return result

    def parse_results(self, raw_output: str, url: str = "") -> list[Finding]:
        """One finding per plugin with a failed test; errored tests are not counted."""
        try:
            entries = json.loads(raw_output)["results"]["results"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise MalformedOutputError(str(exc)) from exc
        if not isinstance(entries, list):
            raise MalformedOutputError("results.results is not a list")
        counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        first_error: dict[str, str] = {}
        for entry in entries:
            plugin = self._redact(_plugin_id(entry)) if isinstance(entry, dict) else ""
            if not plugin or entry.get("failureReason") == ERROR_REASON:
                continue
            counts[plugin][1] += 1
            if entry.get("success") is False:
                counts[plugin][0] += 1
                first_error.setdefault(plugin, str(entry.get("error", "")))
        return [
            tool_finding(
                TOOL,
                plugin,
                url=url,
                label=plugin,
                fails=fails,
                total=total,
                parameter=plugin,
                evidence=self._redact(
                    f"{fails} of {total} tests failed: {first_error[plugin]}"
                ),
                raw_data=self._redact_data(
                    {"plugin": plugin, "fails": fails, "total": total}
                ),
            )
            for plugin, (fails, total) in counts.items()
            if fails > 0
        ]

    def _command(self, *args: str) -> list[str]:
        env = [f"{k}={v}" for k, v in tool_config(TOOL).env.items()]
        return ["env", *env, TOOL, *args, "--no-progress-bar"]

    def _generate_command(self, work: Path) -> list[str]:
        provider = self.options.get("provider")
        if provider is not None and not PROVIDER_ID.match(str(provider)):
            raise ValueError(f"provider {provider!r} is not a valid provider id")
        extra = ["--provider", str(provider)] if provider else []
        return self._command(
            "redteam",
            "generate",
            "-c",
            str(work / CONFIG_NAME),
            "-o",
            str(work / TESTS_NAME),
            *extra,
        )

    def _eval_command(self, work: Path) -> list[str]:
        return [
            *self._command(
                "eval",
                "-c",
                str(work / TESTS_NAME),
                "-o",
                str(work / RESULTS_NAME),
                "--no-cache",
                "--no-write",
                "--no-table",
                "--no-share",
                "--max-concurrency",
                "1",
            ),
            *self._extra_args(),
        ]

    def _step_error(self, step: str, run: ToolRun, timeout: int) -> str:
        if run.timed_out:
            return self._timeout_error(timeout)
        detail = self._redact(run.stderr)[:500]
        return f"promptfoo {step} exited with code {run.returncode}: {detail}"

    def _write_config(self, target: Target, endpoint: Endpoint, work: Path) -> None:
        """Write the config with an ``http`` target; credentials stay in a 0600 file."""
        limits = load_probes().ai
        max_prompts = int(self.options.get("max_prompts", limits.max_prompts))
        max_tokens = int(
            self.options.get("max_tokens_per_prompt", limits.max_tokens_per_prompt)
        )
        plugins = selection(TOOL, self.options.get("plugins"))
        config = {
            "prompts": [PROMPT_VAR],
            "targets": [
                {
                    "id": "http",
                    "label": TOOL,
                    "config": {
                        "url": endpoint.chat_url,
                        "method": "POST",
                        "headers": {
                            "Content-Type": "application/json",
                            **target.auth.as_headers(),
                        },
                        "body": chat_body(endpoint, PROMPT_VAR, max_tokens),
                        "transformResponse": RESPONSE_EXPR,
                    },
                }
            ],
            "redteam": {
                "purpose": tool_config(TOOL).purpose,
                "numTests": max(1, max_prompts // len(plugins)),
                "plugins": plugins,
            },
        }
        write_private(work / CONFIG_NAME, yaml.safe_dump(config))
