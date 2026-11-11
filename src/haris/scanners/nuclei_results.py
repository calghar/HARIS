import json
import logging
from typing import Any

from ..data.scanner_config import (
    get_nuclei_confidence_map,
    get_nuclei_default_template_dirs,
    get_nuclei_exclude_template_ids,
    get_nuclei_meta_tags,
    get_nuclei_remediation_map,
    get_nuclei_severity_map,
    get_nuclei_tag_map,
    get_nuclei_tech_fingerprint_dir,
    get_nuclei_tech_tag_map,
    get_nuclei_tech_workflow_map,
)
from ..models import Confidence, Finding, Severity
from .base import ExternalToolScanner

logger = logging.getLogger(__name__)

_NUCLEI_SEVERITY_MAP: dict[str, Severity] = {
    k: getattr(Severity, v) for k, v in get_nuclei_severity_map().items()
}
_NUCLEI_TAG_MAP = get_nuclei_tag_map()
DEFAULT_TEMPLATE_DIRS = get_nuclei_default_template_dirs()
TECH_FINGERPRINT_DIR = get_nuclei_tech_fingerprint_dir()
TECH_TAG_MAP = get_nuclei_tech_tag_map()
TECH_WORKFLOW_MAP = get_nuclei_tech_workflow_map()
_NUCLEI_CONFIDENCE_MAP: dict[str, Confidence] = {
    k: getattr(Confidence, v) for k, v in get_nuclei_confidence_map().items()
}
EXCLUDED_TEMPLATE_IDS = frozenset(get_nuclei_exclude_template_ids())


def _derive_tags(
    template_id: str,
    matcher_name: str,
    nuclei_tags: list[str],
) -> list[str]:
    """Map template tags, matcher name and id to internal OWASP tags.

    Falls back to ``["security_misconfiguration"]`` when nothing matches.
    """
    owasp_tags: list[str] = []
    seen: set[str] = set()

    candidates = [t.lower() for t in nuclei_tags]
    if matcher_name:
        candidates.append(matcher_name.lower())
    if template_id:
        candidates.append(template_id.lower())

    for candidate in candidates:
        for key, mapped_tags in _NUCLEI_TAG_MAP.items():
            if key in candidate:
                for tag in mapped_tags:
                    if tag not in seen:
                        owasp_tags.append(tag)
                        seen.add(tag)

    return owasp_tags if owasp_tags else ["security_misconfiguration"]


class NucleiResults(ExternalToolScanner):
    """Nuclei JSONL parsing; ``NucleiScanner`` adds the process orchestration."""

    _NUCLEI_META_TAGS: frozenset[str] = get_nuclei_meta_tags()

    def parse_results(self, raw_output: str) -> list[Finding]:
        """Parse Nuclei JSONL; unparseable lines and excluded templates are skipped."""
        findings: list[Finding] = []

        for line_num, line in enumerate(raw_output.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue

            try:
                result = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "Skipping unparseable Nuclei JSONL line %d: %s", line_num, exc
                )
                continue

            if result.get("template-id") in EXCLUDED_TEMPLATE_IDS:
                continue
            finding = self._result_to_finding(result)
            if finding is not None:
                findings.append(finding)

        return findings

    def _result_to_finding(self, result: dict[str, Any]) -> Finding | None:
        """Convert one Nuclei result dict to a :class:`Finding`."""
        template_id: str = result.get("template-id", "")
        info: dict[str, Any] = result.get("info", {})

        name: str = info.get("name", template_id or "Unknown finding")
        description: str = info.get("description", "")
        severity_raw: str = info.get("severity", "info").lower()
        nuclei_tags: list[str] = info.get("tags", [])
        matcher_name: str = result.get("matcher-name", "")
        matched_at: str = result.get("matched-at", "")
        extracted: list[str] = result.get("extracted-results", [])
        # With -or nuclei omits the raw request; curl-command still describes it.
        request_example: str = self._redact(
            result.get("request") or result.get("curl-command", "")
        )
        response_snippet: str = self._redact(result.get("response", ""))

        if not name and not template_id:
            logger.debug("Skipping Nuclei result with no name or template-id")
            return None

        severity = _NUCLEI_SEVERITY_MAP.get(severity_raw, Severity.INFO)
        confidence = _NUCLEI_CONFIDENCE_MAP.get(severity_raw, Confidence.TENTATIVE)
        tags = _derive_tags(template_id, matcher_name, nuclei_tags)

        raw_refs = info.get("reference", [])
        if isinstance(raw_refs, str):
            raw_refs = [raw_refs]
        references: list[str] = [r for r in raw_refs if isinstance(r, str)]

        classification: dict[str, Any] = info.get("classification", {})
        cve_ids: list[str] = classification.get("cve-id", []) or []
        cwe_ids: list[str] = classification.get("cwe-id", []) or []
        cvss_score: float | None = classification.get("cvss-score")

        for cve in cve_ids:
            cve_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
            if cve_url not in references:
                references.append(cve_url)

        if cve_ids:
            title = f"{name} ({', '.join(cve_ids)})"
        elif matcher_name:
            title = f"{name} [{matcher_name}]"
        else:
            title = name

        evidence_parts: list[str] = []
        if extracted:
            evidence_parts.append(
                f"Extracted: {self._redact('; '.join(extracted[:5]))}"
            )
        if response_snippet:
            evidence_parts.append(f"Response snippet: {response_snippet[:300]}")
        evidence = "\n".join(evidence_parts)

        remediation: str = info.get("remediation", "")
        if not remediation:
            remediation = self._generic_remediation(tags, severity)

        raw_data: dict[str, Any] = {
            "template-id": template_id,
            "matcher-name": matcher_name,
            "matched-at": matched_at,
            "nuclei-tags": nuclei_tags,
            "extracted-results": extracted,
            "cve-id": cve_ids,
            "cwe-id": cwe_ids,
        }
        if cvss_score is not None:
            raw_data["cvss-score"] = cvss_score

        return Finding(
            title=title[:200],
            description=description or name,
            severity=severity,
            confidence=confidence,
            cwe_id=cwe_ids[0] if cwe_ids else "",
            url=matched_at,
            evidence=evidence,
            request_example=request_example,
            response_snippet=response_snippet[:500],
            remediation=remediation,
            references=references,
            scanner=self.name,
            tags=tags,
            raw_data=self._redact_data(raw_data),
        )

    @staticmethod
    def _extract_technologies(findings: list[Finding]) -> list[str]:
        """Extract technology names from Phase 1 fingerprinting results.

        Uses ``matcher-name``, the first word of ``extracted-results`` and the
        template tags (minus generic metadata tags).
        """
        techs: list[str] = []
        seen: set[str] = set()

        for finding in findings:
            raw = finding.raw_data or {}

            matcher = raw.get("matcher-name", "")
            if matcher and matcher.lower() not in seen:
                techs.append(matcher.lower())
                seen.add(matcher.lower())

            extracted = raw.get("extracted-results", [])
            if isinstance(extracted, list):
                for val in extracted:
                    if isinstance(val, str) and val.strip():
                        # e.g. "Astro v5.15.9" -> "astro"
                        tech_name = val.split()[0].lower().rstrip(",;:")
                        if tech_name and tech_name not in seen:
                            techs.append(tech_name)
                            seen.add(tech_name)

            for tag in raw.get("nuclei-tags", []):
                tag_lower = tag.lower()
                if (
                    tag_lower not in seen
                    and tag_lower not in NucleiResults._NUCLEI_META_TAGS
                ):
                    techs.append(tag_lower)
                    seen.add(tag_lower)

        return techs

    @staticmethod
    def _generic_remediation(tags: list[str], severity: Severity) -> str:  # noqa: ARG004
        """Return a generic remediation hint based on assigned tags."""
        remediation_map = get_nuclei_remediation_map()

        for tag in tags:
            if tag in remediation_map:
                return str(remediation_map[tag])

        return str(
            remediation_map.get(
                "_default",
                "Review the identified issue against the relevant security standard "
                "and apply vendor-recommended hardening guidance.",
            )
        )
