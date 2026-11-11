import pytest

from haris.core.vuln_class import get_registry
from haris.models import Finding, Severity

CLEARTEXT_TITLE = (
    "Cleartext submission of password: Password field 'password' "
    "sent in clear text from URL http://127.0.0.1/login"
)


@pytest.mark.parametrize(
    ("scanner", "title", "tags", "template_id", "expected"),
    [
        (
            "wapiti",
            CLEARTEXT_TITLE,
            ["cleartext_transmission"],
            "",
            "cleartext_password_submission",
        ),
        (
            "nuclei",
            "PHPinfo Page - Detect",
            ["security_misconfiguration", "sensitive_data_exposure"],
            "phpinfo-page-detect",
            "sensitive_file",
        ),
        (
            "nuclei",
            "Prometheus Metrics - Detect",
            ["sensitive_data_exposure", "security_misconfiguration"],
            "prometheus-metrics-detect",
            "sensitive_file",
        ),
        (
            "nikto",
            "This might be interesting.",
            ["security_misconfiguration"],
            "",
            "unclassified:nikto:this-might-be-interesting",
        ),
    ],
)
def test_external_alias_classifies_the_finding(
    scanner: str,
    title: str,
    tags: list[str],
    template_id: str,
    expected: str,
) -> None:
    raw = {"template-id": template_id} if template_id else {}
    finding = Finding(
        title=title,
        description=title,
        severity=Severity.INFO,
        scanner=scanner,
        tags=tags,
        url="http://127.0.0.1/x",
        raw_data=raw,
    )
    assert get_registry().classify(finding) == expected


def test_cleartext_password_submission_has_no_oracle() -> None:
    registered = get_registry().classes["cleartext_password_submission"]
    assert (registered.primary_cwe, registered.granularity, registered.oracle) == (
        "CWE-319",
        "parameter",
        "none",
    )
