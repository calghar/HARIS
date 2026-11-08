import json
from typing import Any

from .. import __version__
from ..diff import DiffStatus, diff_reports, report_from_session
from ..models import EvidenceExchange, Finding, ScanSession, ScanState, Severity
from .base import BaseReporter
from .findings import inactive_reason, report_findings, rule_id

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
FINGERPRINT_KEY = "harisFingerprint/v1"
LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub code scanning reads this CVSS-style 0-10 score from the rule.
SECURITY_SEVERITY = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.0,
    Severity.INFO: 0.5,
}
BASELINE_STATES = {DiffStatus.NEW: "new", DiffStatus.UNCHANGED: "unchanged"}


class SARIFReporter(BaseReporter):
    """SARIF 2.1.0 report; refuted and suppressed findings carry ``suppressions``."""

    format_name = "sarif"
    file_extension = ".sarif"

    def generate(self, session: ScanSession) -> str:
        findings = report_findings(session)
        states, absent = self._baseline(session)
        base_url = session.target.base_url
        results = [_result(f, base_url, states.get(f.finding_id)) for f in findings]
        results += [_result(f, base_url, "absent") for f in absent]
        rules = _rules([*findings, *absent])
        index = {r["id"]: n for n, r in enumerate(rules)}
        for result in results:
            result["ruleIndex"] = index[result["ruleId"]]
        run = {
            "tool": {
                "driver": {"name": "HARIS", "version": __version__, "rules": rules}
            },
            "invocations": [_invocation(session)],
            "properties": {"target": base_url},
            "results": results,
        }
        document = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
        return json.dumps(document, indent=2, ensure_ascii=False)

    def _baseline(self, session: ScanSession) -> tuple[dict[str, str], list[Finding]]:
        """Baseline state per finding id, and baseline findings no longer reported."""
        if self.baseline is None:
            return {}, []
        entries = diff_reports(self.baseline, report_from_session(session))
        states = {
            e.finding_id: BASELINE_STATES[e.status]
            for e in entries
            if e.status in BASELINE_STATES
        }
        absent = [
            self.baseline.findings[e.finding_id].finding
            for e in entries
            if e.status == DiffStatus.FIXED
        ]
        return states, absent


def _rules(findings: list[Finding]) -> list[dict[str, Any]]:
    rules = []
    for rid in sorted({rule_id(f) for f in findings}):
        group = [f for f in findings if rule_id(f) == rid]
        worst = min((f.severity for f in group), key=lambda s: s.sort_key)
        cwes = sorted({f.cwe_id for f in group if f.cwe_id})
        text = rid.replace("_", " ")
        rules.append(
            {
                "id": rid,
                "name": text,
                "shortDescription": {"text": text},
                "defaultConfiguration": {"level": LEVELS[worst]},
                "properties": {
                    "tags": ["security", *cwes],
                    "security-severity": f"{SECURITY_SEVERITY[worst]:.1f}",
                },
            }
        )
    return rules


def _result(f: Finding, base_url: str, baseline_state: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": rule_id(f),
        "level": LEVELS[f.severity],
        "message": {"text": ": ".join(p for p in (f.title, f.description) if p)},
        "locations": [_location(f, base_url)],
        "rank": round(f.confidence_score * 100, 1),
        "properties": {
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "confidenceScore": f.confidence_score,
            "verificationTier": f.verification.tier.value,
            "scanner": f.scanner,
            "cwe": f.cwe_id,
        },
    }
    if f.fingerprint:
        result["partialFingerprints"] = {FINGERPRINT_KEY: f.fingerprint}
    exchange = _exchange(f)
    if request := _web_request(f, exchange):
        result["webRequest"] = request
    if response := _web_response(f, exchange):
        result["webResponse"] = response
    if not f.is_active:
        result["suppressions"] = [_suppression(f)]
    if baseline_state:
        result["baselineState"] = baseline_state
    return result


def _location(f: Finding, base_url: str) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {"artifactLocation": {"uri": f.url or base_url}}
    }
    if f.parameter:
        location["logicalLocations"] = [{"name": f.parameter, "kind": "parameter"}]
    return location


def _exchange(f: Finding) -> EvidenceExchange | None:
    exchanges = sorted(f.verification.evidence, key=lambda e: e.role != "probe")
    return exchanges[0] if exchanges else None


def _web_request(f: Finding, exchange: EvidenceExchange | None) -> dict[str, Any]:
    target = (exchange.url if exchange else "") or f.url
    if not target:
        return {}
    request: dict[str, Any] = {
        "target": target,
        "method": (exchange.method if exchange else "") or f.method,
    }
    if exchange and exchange.request_headers:
        request["headers"] = exchange.request_headers
    if exchange and exchange.request_body_excerpt:
        request["body"] = {"text": exchange.request_body_excerpt}
    return request


def _web_response(f: Finding, exchange: EvidenceExchange | None) -> dict[str, Any]:
    response: dict[str, Any] = {}
    if exchange and exchange.status:
        response["statusCode"] = exchange.status
    if exchange and exchange.response_headers:
        response["headers"] = exchange.response_headers
    body = (exchange.response_body_excerpt if exchange else "") or f.response_snippet
    if body:
        response["body"] = {"text": body}
    return response


def _suppression(f: Finding) -> dict[str, Any]:
    suppression: dict[str, Any] = {
        "kind": "external",
        "status": "accepted",
        "justification": inactive_reason(f),
    }
    if f.suppression is not None:
        suppression["properties"] = {
            "author": f.suppression.author,
            "expires": f.suppression.expires,
        }
    return suppression


def _invocation(session: ScanSession) -> dict[str, Any]:
    return {
        "executionSuccessful": session.scan_state == ScanState.COMPLETED,
        "toolExecutionNotifications": [
            {"level": "error", "message": {"text": e}} for e in session.errors
        ],
        "properties": {"scanState": session.scan_state.value},
    }
