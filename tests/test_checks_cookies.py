import pytest
from requests.structures import CaseInsensitiveDict

from haris.checks import cookie_checks
from haris.checks.cookie_checks import CookieSecurityScanner
from haris.checks.cookie_policy import is_session_cookie, lifetime_seconds
from haris.checks.findings import prior
from haris.core.identity import fingerprint
from haris.models import Finding, Severity
from haris.net import ScopedResponse

from .checks_support import html, run_check, site

STRONG = "Secure; HttpOnly; SameSite=Lax"


@pytest.fixture
def scan_cookie(monkeypatch):
    """Scan a page that sets the given cookies (one Set-Cookie header each)."""
    original = cookie_checks.fetch_page

    def scan(*cookies: str, base_url: str = "https://example.com") -> list[Finding]:
        def fake_fetch(client, url):
            resp = original(client, url)
            return ScopedResponse(
                status_code=resp.status_code,
                url=resp.url,
                headers=CaseInsensitiveDict(resp.headers),
                set_cookies=list(cookies),
                content=resp.content,
            )

        monkeypatch.setattr(cookie_checks, "fetch_page", fake_fetch)
        net = site({"/": html()}, base_url=base_url)
        return run_check(CookieSecurityScanner(), net).findings

    return scan


def issue_classes(findings: list[Finding]) -> list[str]:
    return sorted(f.vuln_class for f in findings)


def test_session_cookie_without_flags_yields_one_finding_per_issue(scan_cookie):
    found = scan_cookie("sid=abc; Path=/")

    assert issue_classes(found) == [
        "cookie_missing_httponly",
        "cookie_missing_secure",
        "cookie_samesite",
    ]
    assert len({fingerprint(f) for f in found}) == 3
    assert {f.parameter for f in found} == {"sid"}


def test_each_flag_issue_has_its_own_severity_and_cwe(scan_cookie):
    by_class = {f.vuln_class: f for f in scan_cookie("sid=abc; Path=/")}

    assert by_class["cookie_missing_secure"].severity is Severity.MEDIUM
    assert by_class["cookie_missing_secure"].cwe_id == "CWE-614"
    assert by_class["cookie_missing_httponly"].severity is Severity.LOW
    assert by_class["cookie_missing_httponly"].cwe_id == "CWE-1004"
    assert by_class["cookie_samesite"].cwe_id == "CWE-1275"


def test_samesite_finding_is_not_mapped_to_session_fixation(scan_cookie):
    found = scan_cookie("sid=abc; Secure; HttpOnly")
    [samesite] = found
    assert samesite.cwe_id != "CWE-384"
    assert "session_fixation" not in samesite.tags


def test_hardened_session_cookie_has_no_findings(scan_cookie):
    assert scan_cookie(f"sessionid=abc; Path=/; {STRONG}") == []


@pytest.mark.parametrize(
    "cookie",
    [
        "_ga=GA1.2.3; Path=/",
        "theme=dark",
        "lang=en; Path=/",
        "XSRF-TOKEN=abc; Path=/",
        "csrftoken=abc",
        "_csrf=abc",
    ],
)
def test_non_session_cookies_are_ignored(cookie, scan_cookie):
    assert scan_cookie(cookie) == []


@pytest.mark.parametrize(
    "name",
    ["sid", "session", "PHPSESSID", "connect.sid", "auth_token", "user_sid", "JWT"],
)
def test_session_cookie_name_heuristic_matches(name):
    assert is_session_cookie(name)


@pytest.mark.parametrize(
    "name", ["_ga", "theme", "side", "residence", "csrf_token", "XSRF-TOKEN"]
)
def test_session_cookie_name_heuristic_rejects(name):
    assert not is_session_cookie(name)


def test_only_the_session_cookie_is_judged_among_several(scan_cookie):
    found = scan_cookie("_ga=1; Path=/", "sid=abc; Path=/", "theme=dark")
    assert {f.parameter for f in found} == {"sid"}


def test_secure_flag_is_not_demanded_over_plain_http(scan_cookie):
    found = scan_cookie(
        "sid=abc; HttpOnly; SameSite=Lax", base_url="http://example.com"
    )
    assert found == []


def test_samesite_none_without_secure_is_medium(scan_cookie):
    found = scan_cookie("sid=abc; HttpOnly; SameSite=None")
    none = next(f for f in found if f.vuln_class == "cookie_samesite")
    assert none.severity is Severity.MEDIUM
    assert none.cwe_id == "CWE-1275"


def test_samesite_none_with_secure_is_low(scan_cookie):
    found = scan_cookie("sid=abc; Secure; HttpOnly; SameSite=None")
    assert [f.severity for f in found] == [Severity.LOW]


def test_framework_default_name_is_reported_as_info(scan_cookie):
    found = scan_cookie(f"PHPSESSID=abc; {STRONG}")
    [disclosure] = found
    assert disclosure.vuln_class == "cookie_name_disclosure"
    assert disclosure.severity is Severity.INFO
    assert "PHP" in disclosure.title


def test_public_suffix_domain_is_high(scan_cookie):
    found = scan_cookie(f"sid=abc; Domain=.com; {STRONG}")
    [scope] = found
    assert scope.vuln_class == "cookie_scope"
    assert scope.severity is Severity.HIGH


def test_parent_domain_is_info_and_exact_host_is_clean(scan_cookie):
    parent = scan_cookie(
        f"sid=abc; Domain=.example.com; {STRONG}", base_url="https://app.example.com"
    )
    exact = scan_cookie(
        f"sid=abc; Domain=app.example.com; {STRONG}", base_url="https://app.example.com"
    )

    assert [f.severity for f in parent] == [Severity.INFO]
    assert exact == []


def test_excessive_lifetime_is_flagged_and_normal_lifetime_is_not(scan_cookie):
    long = scan_cookie(f"sid=abc; Max-Age={400 * 86_400}; {STRONG}")
    normal = scan_cookie(f"sid=abc; Max-Age={30 * 86_400}; {STRONG}")

    assert issue_classes(long) == ["cookie_lifetime"]
    assert "400 days" in long[0].title
    assert normal == []


def test_lifetime_uses_max_age_before_expires():
    attrs = {"max-age": "60", "expires": "Wed, 01 Jan 2200 00:00:00 GMT"}
    assert lifetime_seconds(attrs) == 60
    assert lifetime_seconds({"expires": "Wed, 01 Jan 2200 00:00:00 GMT"}) > 365 * 86_400
    assert lifetime_seconds({}) is None


def test_confidence_comes_from_config_priors(scan_cookie):
    found = scan_cookie("PHPSESSID=abc; Path=/; Secure; SameSite=Lax")
    flags = {f.vuln_class: f for f in found}

    assert flags["cookie_missing_httponly"].confidence_score == prior(
        "cookie_checks.session_flag"
    )
    assert flags["cookie_name_disclosure"].confidence_score == prior(
        "cookie_checks.name_disclosure"
    )
    assert scan_cookie("sid=1")[-1].confidence_score in {
        prior("cookie_checks.session_flag"),
        prior("cookie_checks.session_attribute"),
    }
