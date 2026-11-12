import logging
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, date, datetime
from typing import Any

from ..agent.stages import note_stage
from ..ignore import IgnoreFile, apply_ignores
from ..models import (
    Finding,
    ScannerResult,
    ScannerStatus,
    ScanSession,
    ScanState,
    Target,
)
from ..models.scan_context import ScanContext
from ..net import NetworkError, NetworkPolicy, ScopedClient
from ..net.ssrf import Resolver, system_resolver
from ..verify.settings import VerifyMode
from .confidence import prior_for
from .context_extract import extract_context
from .correlator import FindingCorrelator, pick_best
from .decorators import check_registry
from .identity import assign_identity
from .llm_enrichment import run_llm_enrichment
from .owasp import map_class_to_owasp, map_to_owasp
from .remediation import RemediationPlanner
from .risk import assess_risk_posture, risk_posture_summary
from .scanner import BaseScanner
from .tool_vet import egress_proxy_for, external_target_block
from .vuln_class import get_registry

logger = logging.getLogger(__name__)

DEFAULT_PARALLEL = 3
MIN_TOOL_RATE_RPS = 1.0
RECON_SCANNERS = frozenset({"nmap"})
DONE_STATUSES = frozenset({ScannerStatus.COMPLETED, ScannerStatus.PARTIAL})


class ScanEngine:
    """Orchestrates a full security audit.

    Stages: ``recon`` (built-in checks and nmap, sequential, fills the
    ``ScanContext``), ``scan`` (remaining scanners in parallel with a read-only
    context), then identity, correlation, ignore file, risk and remediation.

    Usage::

        engine = ScanEngine(scanners=[WapitiScanner(), SSLyzeScanner()])
        session = engine.run(target, config)
    """

    def __init__(
        self,
        scanners: list[BaseScanner] | None = None,
        session_id: str | None = None,
        template_manager: Any | None = None,
        llm_backend: Any | None = None,
        llm_config: dict[str, Any] | None = None,
        *,
        parallel: int = DEFAULT_PARALLEL,
        network_policy: NetworkPolicy | None = None,
        resolver: Resolver | None = None,
        ignore: IgnoreFile | None = None,
        today: date | None = None,
        checkpoint: Callable[[ScanSession], None] | None = None,
        verify: VerifyMode = VerifyMode.OFF,
    ) -> None:
        self.scanners: list[BaseScanner] = scanners or []
        self.session_id = session_id or datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        self.parallel = max(1, parallel)
        self.http: ScopedClient | None = None
        self._correlator = FindingCorrelator()
        self._planner = RemediationPlanner()
        self._template_manager = template_manager
        self._llm_backend = llm_backend
        self._llm_config: dict[str, Any] = llm_config or {}
        self._network_policy = network_policy or NetworkPolicy()
        self._resolver = resolver
        self._ignore = ignore
        self._today = today
        self._checkpoint = checkpoint
        self._verify_mode = verify
        self._cancelled = threading.Event()

    def add_scanner(self, scanner: BaseScanner) -> None:
        self.scanners.append(scanner)

    def cancel(self) -> None:
        """Stop starting scanners; the scan ends in state ``cancelled``."""
        self._cancelled.set()

    # Run

    def run(
        self,
        target: Target,
        config: dict[str, Any] | None = None,
    ) -> ScanSession:
        """Execute all registered scanners against *target*."""
        config = config or {}
        session = ScanSession(
            session_id=self.session_id,
            target=target,
            started_at=datetime.now(UTC).isoformat(),
            scanners_used=[s.name for s in self.scanners],
            scan_state=ScanState.RUNNING,
        )
        logger.info(
            "Starting audit session %s against %s", self.session_id, target.base_url
        )

        with ScopedClient(
            target,
            self._network_policy,
            resolver=self._resolver or system_resolver,
        ) as client:
            self.http = client
            self._run_stages(session, target, config, client)
            session.scan_state = self._final_state(session)
            self._enrich_findings(session)
            self._correlate_findings(session)
            note_stage(session, "correlate")
            self._apply_ignores(session)
            note_stage(session, "suppress")
            if not self._cancelled.is_set():
                from ..verify import run_verification  # lazy: verify imports core

                run_verification(
                    session,
                    client,
                    self._verify_mode,
                    self._llm_backend,
                    cancel=self._cancelled,
                )
            if client.budget_exceeded:
                session.errors.append(
                    "[net] request cap max_requests="
                    f"{target.scope.max_requests} reached; later requests were refused"
                )

        session.finished_at = datetime.now(UTC).isoformat()
        self._assess_risk(session)
        note_stage(session, "risk")
        self._plan_remediation(session)

        if self._llm_backend and self._llm_config.get("enrichment_enabled"):
            self._llm_enrich(session)

        note_stage(session, "report")
        logger.info(
            "Audit session %s %s - %d findings (%d correlated), "
            "risk posture: %s, %.1fs",
            self.session_id,
            session.scan_state.value,
            len(session.all_findings),
            len(session.correlated),
            session.risk_posture.value,
            session.duration_seconds,
        )
        return session

    # Stages

    def _run_stages(
        self,
        session: ScanSession,
        target: Target,
        config: dict[str, Any],
        client: ScopedClient,
    ) -> None:
        try:
            target_ip = client.preflight(target.base_url)
        except NetworkError as exc:
            logger.error("Pre-flight blocked the scan: %s", exc)
            for scanner in self.scanners:
                self._record(
                    session,
                    scanner,
                    ScannerResult(
                        scanner_name=scanner.name,
                        errors=[f"not started, pre-flight failed: {exc}"],
                    ),
                )
            return

        proxy = egress_proxy_for(
            self.scanners, target, target_ip, self._network_policy, self._resolver
        )
        context = ScanContext(
            http=client,
            target_ip=target_ip,
            egress_proxy=proxy.start() if proxy else "",
        )
        recon = [s for s in self.scanners if self._is_recon(s)]
        rest = [s for s in self.scanners if not self._is_recon(s)]
        rps = target.scope.rate_limit_rps
        try:
            for stage, workers in ((recon, 1), (rest, self.parallel)):
                concurrent = max(1, min(workers, len(stage)))
                context.tool_rate_rps = max(MIN_TOOL_RATE_RPS, rps / concurrent)
                self._run_stage(stage, workers, session, target, config, context)
        finally:
            if proxy:
                proxy.close()

    @staticmethod
    def _is_recon(scanner: BaseScanner) -> bool:
        return scanner.name in RECON_SCANNERS or scanner.name in check_registry()

    def _run_stage(
        self,
        scanners: list[BaseScanner],
        workers: int,
        session: ScanSession,
        target: Target,
        config: dict[str, Any],
        context: ScanContext,
    ) -> None:
        if not scanners:
            return
        # Only the recon stage may write to the context; the scan stage reads it.
        writes_context = workers == 1
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    self._execute, s, target, config.get(s.name, {}), context
                ): s
                for s in scanners
            }
            for future in as_completed(futures):
                scanner = futures[future]
                result = future.result()
                if result is None:
                    continue
                self._record(session, scanner, result)
                if writes_context:
                    extract_context(scanner.name, result, context)

    def _execute(
        self,
        scanner: BaseScanner,
        target: Target,
        scanner_config: dict[str, Any],
        context: ScanContext,
    ) -> ScannerResult | None:
        """Run one scanner; a raised exception becomes a failed result."""
        if self._cancelled.is_set():
            logger.info("Skipping %s: scan cancelled", scanner.name)
            return None
        logger.info("Running scanner: %s", scanner.name)
        start = time.monotonic()
        try:
            if self._template_manager:
                template_opts = self._template_manager.get_scanner_options(scanner.name)
                if template_opts:
                    scanner_config = {**template_opts, **scanner_config}
            if scanner_config:
                scanner.configure(scanner_config)
            blocked = external_target_block(
                scanner, target, self._network_policy, self._resolver
            )
            result = (
                ScannerResult(scanner_name=scanner.name, errors=[blocked])
                if blocked
                else scanner.scan(target, context=context)
            )
        except Exception as exc:
            logger.exception("Scanner %s failed with an exception", scanner.name)
            result = ScannerResult(
                scanner_name=scanner.name,
                errors=[f"failed with an exception: {type(exc).__name__}: {exc}"],
            )
        elapsed = time.monotonic() - start
        result.metadata["elapsed_seconds"] = round(elapsed, 2)
        logger.info(
            "Scanner %s finished: %d findings, %d errors in %.1fs",
            scanner.name,
            len(result.findings),
            len(result.errors),
            elapsed,
        )
        return result

    def _record(
        self, session: ScanSession, scanner: BaseScanner, result: ScannerResult
    ) -> None:
        """Merge one result into the session and checkpoint it (main thread)."""
        for finding in result.findings:
            if not finding.scanner:
                finding.scanner = scanner.name
        session.scanner_results.append(result)
        session.all_findings.extend(result.findings)
        session.errors.extend(f"[{scanner.name}] {e}" for e in result.errors)
        if self._checkpoint is not None:
            try:
                self._checkpoint(session)
            except Exception:
                logger.exception("Checkpoint after %s failed", scanner.name)

    def _final_state(self, session: ScanSession) -> ScanState:
        if self._cancelled.is_set():
            return ScanState.CANCELLED
        status = session.scanner_status
        if not status:
            return ScanState.FAILED if self.scanners else ScanState.COMPLETED
        counted = [s for s in status.values() if s != ScannerStatus.SKIPPED]
        if not counted:
            return ScanState.COMPLETED
        done = sum(s in DONE_STATUSES for s in counted)
        if done == 0:
            return ScanState.FAILED
        return ScanState.COMPLETED if done == len(counted) else ScanState.INCOMPLETE

    # Post-processing

    def _enrich_findings(self, session: ScanSession) -> None:
        """Tag OWASP, assign identity, keep the best finding per fingerprint."""
        base_url = session.target.base_url
        buckets: dict[str, list[Finding]] = defaultdict(list)
        registry = get_registry()
        for finding in session.all_findings:
            if not finding.owasp_category:
                self._auto_map_owasp(finding, registry.classify(finding))
            assign_identity(finding, base_url)
            buckets[finding.fingerprint].append(finding)

        best = [pick_best(bucket) for bucket in buckets.values()]
        session.all_findings = sorted(
            best, key=lambda f: (f.severity.sort_key, -prior_for(f))
        )

    def _correlate_findings(self, session: ScanSession) -> None:
        """Cross-tool correlation over every observation, not just the kept ones."""
        session.correlated = self._correlator.correlate(
            self._all_observations(session), session.target.base_url
        )

    @staticmethod
    def _all_observations(session: ScanSession) -> list[Finding]:
        return [f for r in session.scanner_results for f in r.findings]

    def _apply_ignores(self, session: ScanSession) -> None:
        if self._ignore is None:
            return
        canonicals = [c.canonical for c in session.correlated]
        count = apply_ignores(
            [*session.all_findings, *canonicals],
            self._ignore,
            base_url=session.target.base_url,
            today=self._today,
        )
        logger.info("Ignore file suppressed %d findings", count)

    def _assess_risk(self, session: ScanSession) -> None:
        """Compute overall risk posture from the correlated findings."""
        status = session.scanner_status
        session.risk_posture = assess_risk_posture(
            session.correlated,
            scanner_completed=any(s in DONE_STATUSES for s in status.values()),
        )
        session.risk_posture_text = risk_posture_summary(session.risk_posture)

    def _plan_remediation(self, session: ScanSession) -> None:
        """Generate a prioritised remediation checklist."""
        session.remediation_steps = self._planner.plan(
            [c.canonical for c in session.correlated if c.canonical.is_active]
        )

    _extract_context = staticmethod(extract_context)

    @staticmethod
    def _auto_map_owasp(finding: Finding, class_id: str) -> None:
        """Set owasp_category from the canonical class, then tags, then title."""
        title_lower = finding.title.lower().replace(" ", "_")
        candidates = (
            map_class_to_owasp(class_id),
            *(map_to_owasp(tag) for tag in finding.tags),
            map_to_owasp(title_lower),
        )
        mapping = next((m for m in candidates if m), None)
        if mapping:
            finding.owasp_category = mapping.category.value
            if not finding.cwe_id and mapping.typical_cwes:
                finding.cwe_id = mapping.typical_cwes[0]

    def _llm_enrich(self, session: ScanSession) -> None:
        run_llm_enrichment(session, self._llm_backend, self._llm_config)
