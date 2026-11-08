import logging

from ..llm.backend import BaseLLMBackend
from ..models import ScanSession
from ..net import ScopedClient
from .llm_verdict import run_llm_verdicts
from .replay import replay
from .settings import VerifyMode, VerifySettings, load_verify_settings

logger = logging.getLogger(__name__)


def run_verification(
    session: ScanSession,
    client: ScopedClient,
    mode: VerifyMode | str,
    backend: BaseLLMBackend | None = None,
    settings: VerifySettings | None = None,
) -> None:
    """Replay, then (mode ``llm``) LLM verdicts, on ``session.correlated``."""
    mode = VerifyMode(mode)
    if mode == VerifyMode.OFF:
        return
    settings = settings or load_verify_settings()
    report = replay(session.correlated, client, settings)
    if report.skipped:
        reasons = sorted(set(report.skipped.values()))
        session.errors.append(
            f"[verify] {len(report.skipped)} finding(s) not replayed: "
            + "; ".join(reasons)
        )
    if mode == VerifyMode.LLM:
        if backend is None:
            session.errors.append("[verify] llm verdict skipped: no LLM backend")
        else:
            session.errors.extend(
                f"[verify] {e}"
                for e in run_llm_verdicts(session.correlated, backend, settings)
            )
    sync_findings(session)


def sync_findings(session: ScanSession) -> None:
    """Copy verification and score from each canonical to its ``all_findings`` entry."""
    canonical = {c.canonical.fingerprint: c.canonical for c in session.correlated}
    for finding in session.all_findings:
        source = canonical.get(finding.fingerprint)
        if source is not None and source.verification != finding.verification:
            finding.verification = source.verification.model_copy(deep=True)
            finding.confidence_score = source.confidence_score
            finding.confidence = source.confidence
