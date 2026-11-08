from haris.models import (
    CorrelatedFinding,
    EvidenceExchange,
    Finding,
    ScannerResult,
    ScanSession,
    ScanState,
    Severity,
    Suppression,
    Target,
    Verification,
    VerificationMethod,
    VerificationTier,
)

BASE = "https://example.com"


def make_finding(**kwargs: object) -> Finding:
    values: dict[str, object] = {
        "title": "Reflected XSS in q",
        "description": "q is reflected unescaped.",
        "severity": Severity.HIGH,
        "confidence_score": 0.8,
        "url": f"{BASE}/search?q=x",
        "parameter": "q",
        "vuln_class": "xss_reflected",
        "fingerprint": "a" * 64,
        "finding_id": "f1",
        "cwe_id": "CWE-79",
        "scanner": "wapiti",
        "response_snippet": "<html>x</html>",
        **kwargs,
    }
    return Finding.model_validate(values)


def make_session(findings: list[Finding] | None = None) -> ScanSession:
    """Active replay-verified XSS, a suppressed finding and a refuted one."""
    probe = EvidenceExchange(
        method="GET",
        url=f"{BASE}/search?q=%3Cx%3E",
        request_headers={"Accept": "text/html"},
        status=200,
        response_headers={"Content-Type": "text/html"},
        response_body_excerpt="<html><x></html>",
    )
    active = make_finding(
        verification=Verification(
            tier=VerificationTier.REPLAY_VERIFIED,
            method=VerificationMethod.REPLAY,
            evidence=[probe],
        )
    )
    suppressed = make_finding(
        finding_id="f2",
        title="Missing HSTS",
        severity=Severity.MEDIUM,
        vuln_class="missing_hsts",
        fingerprint="b" * 64,
        cwe_id="CWE-319",
        parameter="",
        url=BASE,
        suppression=Suppression(
            reason="accepted risk", author="qa", expires="2099-01-01"
        ),
    )
    refuted = make_finding(
        finding_id="f3",
        title="Backup file exposed",
        severity=Severity.LOW,
        vuln_class="exposed_backup",
        fingerprint="c" * 64,
        url=f"{BASE}/a.bak",
        parameter="",
        verification=Verification(tier=VerificationTier.REFUTED),
    )
    chosen = findings if findings is not None else [active, suppressed, refuted]
    return ScanSession(
        session_id="s-1",
        target=Target(base_url=BASE),
        started_at="2026-01-01T10:00:00+00:00",
        finished_at="2026-01-01T10:05:00+00:00",
        scanners_used=["wapiti"],
        scan_state=ScanState.COMPLETED,
        scanner_results=[ScannerResult(scanner_name="wapiti")],
        all_findings=chosen,
        correlated=[
            CorrelatedFinding(canonical=f, sources=[(f.scanner, f.observation_id)])
            for f in chosen
        ],
    )
