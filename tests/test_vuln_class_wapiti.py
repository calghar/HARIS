import json

import pytest

from haris.core.vuln_class import get_registry
from haris.scanners.wapiti_scanner import WapitiScanner

VULNS = {
    "Command execution": ("ip", "Command execution vulnerability in the parameter ip"),
    "Cross Site Request Forgery": ("", "Lack of anti CSRF token"),
    "Unrestricted File Upload": (
        "uploaded",
        "Unrestricted file upload vulnerability in the parameter uploaded",
    ),
    "Path Traversal": ("page", "Path Traversal vulnerability in the parameter page"),
    "Reflected Cross Site Scripting": ("q", "XSS vulnerability in the parameter q"),
    "Blind SQL Injection": ("id", "Blind SQL vulnerability in the parameter id"),
    "Weak credentials": ("", "Credentials found: admin / admin"),
}


def classes_by_category() -> dict[str, str]:
    report = {
        "vulnerabilities": {
            category: [
                {"info": info, "parameter": param, "path": "/p", "method": "POST"}
            ]
            for category, (param, info) in VULNS.items()
        }
    }
    findings = WapitiScanner().parse_results(json.dumps(report))
    registry = get_registry()
    return {f.title.split(":")[0]: registry.classify(f) for f in findings}


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        ("Command execution", "command_injection"),
        ("Cross Site Request Forgery", "csrf"),
        ("Unrestricted File Upload", "unrestricted_upload"),
        ("Path Traversal", "path_traversal"),
        ("Reflected Cross Site Scripting", "xss_reflected"),
        ("Blind SQL Injection", "sqli_time"),
        (
            "Weak credentials",
            "unclassified:wapiti:weak-credentials-credentials-found-admin-admin",
        ),
    ],
)
def test_wapiti_category_resolves_to_class(category: str, expected: str) -> None:
    assert classes_by_category()[category] == expected


@pytest.mark.parametrize(
    ("class_id", "cwe", "granularity"),
    [
        ("command_injection", "CWE-78", "parameter"),
        ("csrf", "CWE-352", "path"),
        ("unrestricted_upload", "CWE-434", "parameter"),
    ],
)
def test_new_classes_are_registered_without_oracle(
    class_id: str, cwe: str, granularity: str
) -> None:
    registered = get_registry().classes[class_id]
    assert (registered.primary_cwe, registered.granularity) == (cwe, granularity)
    assert registered.oracle == "none"
