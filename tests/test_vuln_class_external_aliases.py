import pytest

from haris.core.vuln_class import get_registry
from haris.models import Finding, Severity
from haris.verify.oracles import header_name

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
            "phpinfo-files",
            "sensitive_file",
        ),
        (
            "nuclei",
            "Prometheus Metrics - Detect",
            ["security_misconfiguration", "sensitive_data_exposure"],
            "prometheus-metrics",
            "sensitive_file",
        ),
        (
            "nuclei",
            "Springboot Env Actuator - Detect",
            ["security_misconfiguration", "sensitive_data_exposure"],
            "springboot-env",
            "sensitive_file",
        ),
        (
            "nuclei",
            "GoCd Encryption Key",
            ["security_misconfiguration", "sensitive_data_exposure"],
            "gocd-encryption-key",
            "sensitive_file",
        ),
        (
            "nuclei",
            "Tomcat Stack Traces Enabled",
            ["security_misconfiguration"],
            "tomcat-stacktraces",
            "unclassified:nuclei:tomcat-stack-traces-enabled",
        ),
        (
            "nikto",
            "Suggested security header missing: content-security-policy.",
            ["security_misconfiguration"],
            "",
            "missing_header",
        ),
        (
            "nikto",
            "The X-Content-Type-Options header is not set. This could allow it.",
            ["security_misconfiguration"],
            "",
            "missing_header",
        ),
        (
            "nikto",
            "Retrieved x-powered-by header: PHP/8.5.11.",
            ["outdated_server"],
            "",
            "banner_disclosure",
        ),
        (
            "nikto",
            "PHP Easter Eggs reveals potentially sensitive information via HTTP.",
            ["security_misconfiguration"],
            "",
            "banner_disclosure",
        ),
        (
            "nikto",
            "Retrieved access-control-allow-origin header: *.",
            ["security_misconfiguration"],
            "",
            "cors_misconfiguration",
        ),
        (
            "nikto",
            "contains 1 entry which should be manually viewed.",
            ["security_misconfiguration"],
            "",
            "sensitive_file",
        ),
        (
            "nikto",
            "contains 3 entries which should be manually viewed.",
            ["security_misconfiguration"],
            "",
            "sensitive_file",
        ),
        (
            "nikto",
            "/phpinfo.php: Output from the phpinfo() function was found.",
            ["security_misconfiguration", "outdated_component"],
            "",
            "sensitive_file",
        ),
        (
            "nikto",
            "PHP is installed, and a test script which runs phpinfo() was found.",
            ["security_misconfiguration", "outdated_component"],
            "",
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


@pytest.mark.parametrize(
    ("title", "header"),
    [
        ("Missing X-Frame-Options header", "X-Frame-Options"),
        (
            "Suggested security header missing: content-security-policy.",
            "content-security-policy",
        ),
        (
            "The X-Content-Type-Options header is not set. This could allow it.",
            "X-Content-Type-Options",
        ),
        ("Retrieved x-powered-by header: PHP/8.5.11.", ""),
    ],
)
def test_header_oracle_reads_the_header_from_scanner_titles(
    title: str, header: str
) -> None:
    finding = Finding(title=title, description=title, severity=Severity.INFO)
    assert header_name(finding) == header
