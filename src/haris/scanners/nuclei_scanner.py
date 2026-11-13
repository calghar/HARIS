import logging
import tempfile
import time
from pathlib import Path
from typing import Any

from ..core.decorators import handle_scanner_errors
from ..data.scanner_config import (
    check_nuclei_phase2_timeout,
    get_nuclei_deny_tags,
    get_nuclei_exclude_template_types,
    get_nuclei_max_selected_tags,
    get_nuclei_max_tag_templates,
    get_nuclei_min_tag_templates,
    get_nuclei_phase2_timeout,
    get_nuclei_unproxied_template_types,
)
from ..models import Finding, ScannerResult, Target
from ..models.scan_context import ScanContext
from .nuclei_argv import build_argv, map_technologies
from .nuclei_results import BASELINE_TEMPLATE_DIRS, NucleiResults
from .nuclei_selection import (
    SelectionResult,
    merge_tags,
    read_allowlist,
    select_tags,
    selection_note,
)
from .nuclei_templates import TEMPLATES_CONFIG_FILE, config_dir_from, templates_dir_from
from .nuclei_urls import filter_discovered_urls
from .process import ToolTimeoutError
from .redaction import redact_argv

logger = logging.getLogger(__name__)

VERSION_TIMEOUT_SECONDS = 30
MAX_URL_LIST = 500
EXPLICIT_OPTIONS = "explicit template options"


class NucleiScanner(NucleiResults):
    """Adapter for the Nuclei template-based vulnerability scanner (3.x).

    Phase 2 runs the tag group (deterministic and LLM-selected tags, or ``-as``
    when there are none) and then the baseline group (``baseline_template_dirs``)
    under one deadline; only the tag group gets the URL list, the baseline group
    runs on the base URL. Explicit ``template_dirs`` or ``tags`` replace both groups
    with one run and the tag selector is not called.

    Options: ``timeout`` (seconds per run), ``phase2_timeout_s`` (seconds for
    all of Phase 2; overrides ``nuclei.yaml``), ``template_dirs``, ``templates``,
    ``tags``, ``severity``, ``exclude_tags``, ``rate_limit``, ``concurrency``,
    ``bulk_size``, ``max_host_errors`` (``-mhe``), ``timeout_per_request``,
    ``retries`` (``-retries``), ``enable_interactsh``, ``automatic_scan`` (also
    add ``-as`` to the tag group), ``update_templates`` (run ``-ut`` first),
    ``extra_args``.
    """

    name = "nuclei"
    binds_to = "egress_proxy"
    version = "3.x"
    description = "Template-based CVE, misconfiguration, and exposure scanner"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 3600)
        self.options.setdefault("templates", [])
        self.options.setdefault("tags", [])
        self.options.setdefault("severity", [])
        self.options.setdefault("exclude_tags", [])
        self.options.setdefault("rate_limit", 100)
        self.options.setdefault("max_host_errors", 500)
        self.options.setdefault("concurrency", 10)
        self.options.setdefault("bulk_size", 10)
        self.options.setdefault("template_dirs", [])
        self.options.setdefault("extra_args", [])
        self.options.setdefault("enable_interactsh", False)
        self.options.setdefault("automatic_scan", False)
        self.options.setdefault("update_templates", False)
        self.options.setdefault("timeout_per_request", 30)
        self.options.setdefault("retries", 2)
        self._root_resolved = False
        self._root: Path | None = None
        self.phase2_stopped = False
        self.phase_durations_s: dict[str, float] = {}

    def _template_root(self) -> Path | None:
        """Template root from nuclei's own config, cached per scanner."""
        if self._root_resolved:
            return self._root
        self._root_resolved = True
        try:
            _, out, err = self._run_command(
                ["nuclei", "-version", "-duc"], timeout=VERSION_TIMEOUT_SECONDS
            )
        except RuntimeError as exc:
            logger.warning("Could not read nuclei config: %s", exc)
            return None
        config_dir = config_dir_from(f"{out}\n{err}")
        if config_dir is not None:
            try:
                text = (config_dir / TEMPLATES_CONFIG_FILE).read_text()
            except OSError as exc:
                logger.warning("Could not read nuclei template config: %s", exc)
            else:
                self._root = templates_dir_from(text)
        return self._root

    def _check_templates_available(self) -> bool:
        """Warn when nuclei's template directory is missing; never fatal."""
        root = self._template_root()
        if root is not None and root.is_dir():
            return True
        logger.warning(
            "nuclei template directory not found (%s); run `nuclei -ut` first",
            root or "unresolved",
        )
        return False

    def _update_templates(self) -> list[str]:
        try:
            returncode, _, stderr = self._run_command(
                ["nuclei", "-ut", "-silent"], timeout=self.options["timeout"]
            )
        except RuntimeError as exc:
            return [f"nuclei template update failed: {exc}"]
        if returncode != 0:
            return [f"nuclei template update exited with {returncode}: {stderr[:500]}"]
        return []

    @handle_scanner_errors
    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        if (refusal := self._unbound(target, context)) is not None:
            return refusal
        if not self._check_tool_available("nuclei"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["nuclei is not installed or not on PATH"],
            )
        self._begin(target, context)

        all_findings: list[Finding] = []
        all_errors: list[str] = []
        all_raw: list[str] = []
        self.phase_durations_s = {}
        context = context or ScanContext()

        if self.options["update_templates"]:
            all_errors.extend(self._update_templates())
        self._check_templates_available()

        target_urls = self._build_url_list(target, context)
        runs: list[tuple[str, dict[str, Any]]]
        if self.options.get("template_dirs") or self.options.get("tags"):
            selection = SelectionResult(reason=EXPLICIT_OPTIONS)
            runs = [("phase2-explicit", {})]
        else:
            map_tags, workflows = self._map_tags_and_workflows(context)
            selection = self._select_tags(context)
            tags = merge_tags(map_tags, selection.tags)
            runs = [
                (
                    "phase2-tags",
                    {
                        "extra_tags": tags,
                        "workflows": workflows,
                        "exclude_templates": BASELINE_TEMPLATE_DIRS,
                        "automatic": bool(self.options["automatic_scan"])
                        or not (tags or workflows),
                    },
                ),
                (
                    "phase2-baseline",
                    {"template_dirs": BASELINE_TEMPLATE_DIRS, "url_list": None},
                ),
            ]

        self.phase2_stopped = False
        limit = self._phase2_limit()
        deadline = time.monotonic() + limit
        for label, run_args in runs:
            findings, errors, raw = self._run_phase(
                target,
                phase_label=label,
                deadline=deadline,
                **{"url_list": target_urls, **run_args},
            )
            all_raw.append(raw)
            all_findings.extend(findings)
            all_errors.extend(errors)

        metadata: dict[str, Any] = {
            "phase_durations_s": dict(self.phase_durations_s),
        }
        notes = [selection_note(selection)]
        if self.phase2_stopped:
            metadata["status"] = "partial"
            notes.insert(
                0,
                f"phase 2 stopped at the {limit:g} s limit "
                "(scanners.nuclei.phase2_timeout_s); results so far kept",
            )
        metadata["note"] = "; ".join(notes)
        return ScannerResult(
            scanner_name=self.name,
            raw_output=self._redact("\n".join(all_raw)),
            findings=self._dedupe(all_findings),
            errors=all_errors,
            metadata=metadata,
        )

    def _phase2_limit(self) -> float:
        override = self.options.get("phase2_timeout_s")
        if override is None:
            return get_nuclei_phase2_timeout()
        return check_nuclei_phase2_timeout(override)

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        """Drop repeats of the same template match across phases."""
        seen: set[tuple[Any, ...]] = set()
        unique: list[Finding] = []
        for finding in findings:
            raw = finding.raw_data
            key = (
                raw.get("template-id"),
                raw.get("matcher-name"),
                raw.get("matched-at"),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    def _run_phase(
        self,
        target: Target,
        *,
        template_dirs: list[str] | None = None,
        extra_tags: list[str] | None = None,
        workflows: list[str] | None = None,
        exclude_templates: list[str] | None = None,
        automatic: bool = False,
        url_list: list[str] | None = None,
        phase_label: str = "",
        deadline: float | None = None,
    ) -> tuple[list[Finding], list[str], str]:
        """Run one nuclei invocation; returns (findings, errors, raw_stdout).

        With a monotonic ``deadline`` the run gets the time left; hitting that
        limit sets ``phase2_stopped`` instead of adding an error.
        """
        timeout = float(self.options["timeout"])
        bounded = False
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.phase2_stopped = True
                return [], [], ""
            bounded = remaining <= timeout
            timeout = min(timeout, remaining)
        url_file = (
            self._write_url_list(url_list) if url_list and len(url_list) > 1 else None
        )
        errors: list[str] = []
        started = time.monotonic()
        try:
            cmd = self._build_command(
                target,
                template_dirs=template_dirs,
                extra_tags=extra_tags,
                workflows=workflows,
                exclude_templates=exclude_templates,
                automatic=automatic,
                url_file=url_file,
            )
            logger.info(
                "nuclei [%s] command: %s",
                phase_label,
                redact_argv(cmd, self._secrets),
            )
            try:
                returncode, stdout, stderr = self._run_command(cmd, timeout=timeout)
            except ToolTimeoutError as exc:
                returncode, stdout, stderr = 0, exc.stdout, exc.stderr
                if bounded:
                    self.phase2_stopped = True
                else:
                    errors.append(
                        f"nuclei [{phase_label}] timed out after "
                        f"{self.options['timeout']}s; partial results kept"
                    )
        finally:
            if url_file:
                Path(url_file).unlink(missing_ok=True)

        elapsed = time.monotonic() - started
        self.phase_durations_s[phase_label] = round(elapsed, 1)
        logger.info("nuclei [%s] finished in %.1f s", phase_label, elapsed)

        filtered_stderr = self._redact(
            "\n".join(
                line
                for line in stderr.splitlines()
                if "Unsolicited response" not in line
            ).strip()
        )

        logger.info(
            "nuclei [%s] exit=%d stdout_lines=%d stderr_len=%d",
            phase_label,
            returncode,
            len(stdout.splitlines()),
            len(filtered_stderr),
        )
        if filtered_stderr:
            logger.warning(
                "nuclei [%s] stderr: %s", phase_label, filtered_stderr[:2000]
            )

        has_fatal = (
            "FTL" in filtered_stderr or "no templates provided" in filtered_stderr
        )
        findings: list[Finding] = []
        if returncode > 1 or (returncode != 0 and has_fatal):
            err_detail = filtered_stderr or self._redact(stdout.strip())
            errors.append(
                f"nuclei [{phase_label}] exited with "
                f"code {returncode}: {err_detail[:500]}"
            )
        elif stdout.strip():
            findings = self.parse_results(stdout)

        return findings, errors, stdout

    def _map_tags_and_workflows(
        self, context: ScanContext
    ) -> tuple[list[str], list[str]]:
        """Return the (tags, workflows) the technology maps give for the context."""
        extra_tags, candidates = map_technologies(context.detected_technologies)
        workflows: list[str] = []
        for workflow_path in candidates:
            if workflow_path in workflows:
                continue
            root = self._template_root()
            if root is None or not (root / workflow_path).exists():
                logger.warning(
                    "nuclei workflow not found: %s (template root %s); skipping",
                    workflow_path,
                    root,
                )
                continue
            workflows.append(workflow_path)

        if extra_tags:
            logger.info(
                "Nuclei Phase 2: tech-derived tags: %s", ", ".join(extra_tags[:20])
            )
        if workflows:
            logger.info(
                "Nuclei Phase 2: tech-derived workflows: %s", ", ".join(workflows[:10])
            )

        return extra_tags, workflows

    def _select_tags(self, context: ScanContext) -> SelectionResult:
        """Ask the selector for extra tags; read the allowlist only with a backend."""
        backend = context.llm_backend
        allowed = None
        if backend is not None:
            # -duc: the update check would reach the network outside the egress proxy.
            allowed = read_allowlist(
                lambda cmd: self._run_command(
                    [*cmd, "-duc"], timeout=VERSION_TIMEOUT_SECONDS
                ),
                get_nuclei_deny_tags(),
                get_nuclei_min_tag_templates(),
                get_nuclei_max_tag_templates(),
            )
        return select_tags(
            context, backend, allowed, max_tags=get_nuclei_max_selected_tags()
        )

    @staticmethod
    def _build_url_list(target: Target, context: ScanContext) -> list[str]:
        """Base URL plus in-scope vetted URLs; empty when only the base remains."""
        return filter_discovered_urls(target, context, MAX_URL_LIST)

    def _build_command(
        self,
        target: Target,
        *,
        template_dirs: list[str] | None = None,
        extra_tags: list[str] | None = None,
        workflows: list[str] | None = None,
        exclude_templates: list[str] | None = None,
        automatic: bool = False,
        url_file: str | None = None,
    ) -> list[str]:
        """Build the nuclei argv."""
        return build_argv(
            self.options,
            target.base_url,
            proxy=self._proxy,
            rate_rps=self._rate_rps,
            headers=target.auth.as_headers(),
            extra_args=self._extra_args(),
            excluded_types=list(
                dict.fromkeys(
                    [
                        *get_nuclei_exclude_template_types(),
                        *get_nuclei_unproxied_template_types(),
                    ]
                )
            ),
            template_dirs=template_dirs,
            extra_tags=extra_tags,
            workflows=workflows,
            exclude_templates=exclude_templates,
            automatic=automatic,
            url_file=url_file,
        )

    @staticmethod
    def _write_url_list(urls: list[str]) -> str:
        """Write URLs to a temp file for ``-list``; the caller deletes it."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            prefix="nuclei_urls_",
            delete=False,
        ) as tmp:
            tmp.write("\n".join(urls))
            return tmp.name
