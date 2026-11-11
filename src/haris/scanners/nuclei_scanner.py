import logging
import tempfile
from pathlib import Path
from typing import Any

from ..core.decorators import handle_scanner_errors, register_scanner
from ..data.scanner_config import get_nuclei_exclude_template_types
from ..models import Finding, ScannerResult, Target
from ..models.scan_context import ScanContext
from .nuclei_results import (
    DEFAULT_TEMPLATE_DIRS,
    EXCLUDED_TEMPLATE_IDS,
    TECH_FINGERPRINT_DIR,
    TECH_TAG_MAP,
    TECH_WORKFLOW_MAP,
    NucleiResults,
)
from .nuclei_templates import TEMPLATES_CONFIG_FILE, config_dir_from, templates_dir_from
from .nuclei_urls import filter_discovered_urls
from .process import ToolTimeoutError

logger = logging.getLogger(__name__)

VERSION_TIMEOUT_SECONDS = 30
MAX_URL_LIST = 500
EXCLUDED_SEVERITY = "info"


@register_scanner
class NucleiScanner(NucleiResults):
    """Adapter for the Nuclei template-based vulnerability scanner (3.x).

    Phase 1 fingerprints technologies (reported as technologies, not findings).
    Phase 2a runs the default template dirs without info-level results; Phase 2b
    runs tech-derived tags and workflows over the templates 2a did not cover.
    Explicit ``template_dirs`` or ``tags`` replace the multi-phase strategy.

    Options: ``timeout`` (seconds per phase), ``template_dirs``, ``templates``,
    ``tags``, ``severity``, ``exclude_tags``, ``rate_limit``, ``concurrency``,
    ``bulk_size``, ``max_host_errors`` (``-mhe``), ``timeout_per_request``,
    ``enable_interactsh``, ``skip_tech_detection``, ``automatic_scan`` (``-as``
    for Phase 2b), ``update_templates`` (run ``-ut`` first), ``extra_args``.
    """

    name = "nuclei"
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
        self.options.setdefault("skip_tech_detection", False)
        self.options.setdefault("automatic_scan", False)
        self.options.setdefault("update_templates", False)
        self.options.setdefault("timeout_per_request", 30)
        self._root_resolved = False
        self._root: Path | None = None

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
        if not self._check_tool_available("nuclei"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["nuclei is not installed or not on PATH"],
            )
        self._begin(target)

        all_findings: list[Finding] = []
        all_errors: list[str] = []
        all_raw: list[str] = []
        technologies: list[str] = []
        context = context or ScanContext()

        if self.options["update_templates"]:
            all_errors.extend(self._update_templates())
        self._check_templates_available()

        has_explicit = bool(
            self.options.get("template_dirs") or self.options.get("tags")
        )

        if not has_explicit and not self.options.get("skip_tech_detection"):
            tech_findings, errors, raw = self._run_phase(
                target,
                template_dirs=[TECH_FINGERPRINT_DIR],
                phase_label="phase1-tech",
                phase_one=True,
            )
            all_raw.append(raw)
            all_errors.extend(errors)
            technologies = self._extract_technologies(tech_findings)
            context.add_technologies(technologies)
            logger.info(
                "Nuclei Phase 1: detected %d technologies: %s",
                len(technologies),
                ", ".join(technologies[:20]),
            )

        target_urls = self._build_url_list(target, context)
        dirs, tags, workflows = self._resolve_targeted_selection(context, has_explicit)

        broad, errors, raw = self._run_phase(
            target,
            template_dirs=dirs,
            url_list=target_urls,
            phase_label="phase2-broad",
        )
        all_raw.append(raw)
        all_findings.extend(broad)
        all_errors.extend(errors)

        automatic = bool(self.options["automatic_scan"]) and not has_explicit
        if tags or workflows or automatic:
            targeted, errors, raw = self._run_phase(
                target,
                extra_tags=tags,
                workflows=workflows,
                exclude_templates=dirs,
                automatic=automatic,
                url_list=target_urls,
                phase_label="phase2-targeted",
            )
            all_raw.append(raw)
            all_findings.extend(targeted)
            all_errors.extend(errors)

        return ScannerResult(
            scanner_name=self.name,
            raw_output=self._redact("\n".join(all_raw)),
            findings=self._dedupe(all_findings),
            errors=all_errors,
            metadata={"technologies": technologies},
        )

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
        phase_one: bool = False,
    ) -> tuple[list[Finding], list[str], str]:
        """Run one nuclei invocation; returns (findings, errors, raw_stdout)."""
        url_file = (
            self._write_url_list(url_list) if url_list and len(url_list) > 1 else None
        )
        errors: list[str] = []
        try:
            cmd = self._build_command(
                target,
                template_dirs=template_dirs,
                extra_tags=extra_tags,
                workflows=workflows,
                exclude_templates=exclude_templates,
                automatic=automatic,
                url_file=url_file,
                phase_one=phase_one,
            )
            logger.info(
                "nuclei [%s] command: %s", phase_label, self._redact(" ".join(cmd))
            )
            try:
                returncode, stdout, stderr = self._run_command(
                    cmd, timeout=self.options["timeout"]
                )
            except ToolTimeoutError as exc:
                returncode, stdout, stderr = 0, exc.stdout, exc.stderr
                errors.append(
                    f"nuclei [{phase_label}] timed out after "
                    f"{self.options['timeout']}s; partial results kept"
                )
        finally:
            if url_file:
                Path(url_file).unlink(missing_ok=True)

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

    def _resolve_targeted_selection(
        self,
        context: ScanContext,
        has_explicit: bool,
    ) -> tuple[list[str], list[str], list[str]]:
        """Return (template_dirs, extra_tags, workflows) for Phase 2.

        Explicit user ``template_dirs``/``tags`` are returned as the broad run's
        dirs only; user tags are already merged into that command, so they are
        never repeated as Phase 2b tags.
        """
        if has_explicit:
            return list(self.options.get("template_dirs", [])), [], []

        template_dirs = list(DEFAULT_TEMPLATE_DIRS)
        extra_tags: list[str] = []
        workflows: list[str] = []
        seen_tags: set[str] = set()

        for tech in context.detected_technologies:
            tech_lower = tech.lower()
            for key, tag_list in TECH_TAG_MAP.items():
                if key in tech_lower:
                    for tag in tag_list:
                        if tag not in seen_tags:
                            extra_tags.append(tag)
                            seen_tags.add(tag)

            for key, workflow_path in TECH_WORKFLOW_MAP.items():
                if key in tech_lower and workflow_path not in workflows:
                    root = self._template_root()
                    if root is None or not (root / workflow_path).exists():
                        logger.warning(
                            "nuclei workflow not found: %s (template root %s); "
                            "skipping",
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

        return template_dirs, extra_tags, workflows

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
        phase_one: bool = False,
    ) -> list[str]:
        """Build the nuclei argv.

        ``phase_one`` keeps info-level results and ignores the user severity
        filter so technology fingerprints are never hidden.
        """
        cmd = [
            "nuclei",
            "-jsonl",
            "-or",
            "-ot",
            "-duc",
            "-silent",
            "-no-color",
            "-system-resolvers",
            "-tls-impersonate",
            "-fhr",
            "-retries",
            "2",
            "-mhe",
            str(self.options["max_host_errors"]),
            "-rate-limit",
            str(self.options["rate_limit"]),
            "-c",
            str(self.options["concurrency"]),
            "-bs",
            str(self.options["bulk_size"]),
            "-timeout",
            str(self.options.get("timeout_per_request", 30)),
        ]

        excluded_types = get_nuclei_exclude_template_types()
        if excluded_types:
            cmd.extend(["-ept", ",".join(excluded_types)])
        if EXCLUDED_TEMPLATE_IDS:
            cmd.extend(["-eid", ",".join(sorted(EXCLUDED_TEMPLATE_IDS))])

        if not self.options.get("enable_interactsh"):
            cmd.append("-no-interactsh")

        if url_file:
            cmd.extend(["-list", url_file])
        else:
            cmd.extend(["-u", target.base_url])

        has_template_selection = automatic
        effective_dirs = template_dirs if template_dirs is not None else []
        user_template_dirs = self.options.get("template_dirs", [])

        if user_template_dirs:
            for tdir in user_template_dirs:
                cmd.extend(["-t", tdir])
                has_template_selection = True
        else:
            for tdir in effective_dirs:
                cmd.extend(["-t", tdir])
                has_template_selection = True

            if not effective_dirs:
                for template_path in self.options.get("templates", []):
                    cmd.extend(["-t", template_path])
                    has_template_selection = True

        for workflow_path in workflows or []:
            cmd.extend(["-w", workflow_path])
            has_template_selection = True

        all_tags: list[str] = list(self.options.get("tags", []))
        seen = {t.lower() for t in all_tags}
        for tag in extra_tags or []:
            if tag.lower() not in seen:
                all_tags.append(tag)
                seen.add(tag.lower())
        if all_tags:
            cmd.extend(["-tags", ",".join(all_tags)])
            has_template_selection = True

        if automatic:
            cmd.append("-as")
        if exclude_templates:
            cmd.extend(["-et", ",".join(exclude_templates)])

        if not has_template_selection:
            for tdir in DEFAULT_TEMPLATE_DIRS:
                cmd.extend(["-t", tdir])

        if not phase_one:
            if self.options.get("severity"):
                cmd.extend(["-severity", ",".join(self.options["severity"])])
            else:
                cmd.extend(["-es", EXCLUDED_SEVERITY])

        exclude_tags = list(self.options.get("exclude_tags", []))
        if "dos" not in [t.lower() for t in exclude_tags]:
            exclude_tags.append("dos")
        cmd.extend(["-etags", ",".join(exclude_tags)])

        for header_name, header_value in target.auth.as_headers().items():
            cmd.extend(["-H", f"{header_name}: {header_value}"])

        cmd.extend(self._extra_args())
        return cmd

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
