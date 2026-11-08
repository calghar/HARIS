import xml.etree.ElementTree as ET  # nosec B405

from ..models import Finding, ScanSession
from .base import BaseReporter
from .escape import xml_text
from .findings import inactive_reason, report_findings, rule_id


class JUnitReporter(BaseReporter):
    """JUnit XML: an active finding fails its testcase; others are skipped.

    ElementTree only builds the document here; nothing is parsed.
    """

    format_name = "junit"
    file_extension = ".xml"

    def generate(self, session: ScanSession) -> str:
        findings = report_findings(session)
        failures = sum(f.is_active for f in findings)
        suite = ET.Element(
            "testsuite",
            name="haris",
            tests=str(len(findings)),
            failures=str(failures),
            skipped=str(len(findings) - failures),
            errors="0",
        )
        for f in findings:
            suite.append(_testcase(f))
        root = ET.Element("testsuites")
        root.append(suite)
        return ET.tostring(root, encoding="unicode", xml_declaration=True)


def _testcase(f: Finding) -> ET.Element:
    name = f"{f.title} [{f.method} {f.url}]" if f.url else f.title
    case = ET.Element(
        "testcase",
        classname=xml_text(rule_id(f)),
        name=xml_text(name),
    )
    if not f.is_active:
        ET.SubElement(case, "skipped", message=xml_text(inactive_reason(f)))
        return case
    failure = ET.SubElement(
        case, "failure", message=xml_text(f.title), type=f.severity.value
    )
    failure.text = xml_text(
        "\n".join(
            part
            for part in (
                f.description,
                f"URL: {f.url}" if f.url else "",
                f"Parameter: {f.parameter}" if f.parameter else "",
                f"Evidence: {f.evidence}" if f.evidence else "",
                f"Fingerprint: {f.fingerprint}" if f.fingerprint else "",
            )
            if part
        )
    )
    return case
