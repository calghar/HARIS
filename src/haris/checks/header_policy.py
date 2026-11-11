import re

from pydantic import BaseModel, ConfigDict

from ..models import Severity

HSTS_MIN_MAX_AGE = 15_552_000
HSTS_PRELOAD_MIN_MAX_AGE = 31_536_000
SCRIPT_RESTRICTING = ("script-src", "default-src")
BROAD_SCHEMES = frozenset({"http:", "https:", "data:"})
_MAX_AGE = re.compile(r"^max-age\s*=\s*\"?(\d+)\"?$", re.IGNORECASE)


class PolicyIssue(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    title: str
    description: str
    severity: Severity
    remediation: str


def parse_csp(value: str) -> dict[str, list[str]]:
    """Directive name to its source tokens; the first occurrence of a name wins."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def _add(
    issues: list[PolicyIssue],
    key: str,
    title: str,
    description: str,
    severity: Severity,
    remediation: str,
) -> None:
    issues.append(
        PolicyIssue(
            key=key,
            title=title,
            description=description,
            severity=severity,
            remediation=remediation,
        )
    )


def csp_issues(value: str) -> list[PolicyIssue]:
    directives = parse_csp(value)
    scripts = next((directives[d] for d in SCRIPT_RESTRICTING if d in directives), None)
    issues: list[PolicyIssue] = []

    if scripts is None:
        _add(
            issues,
            "no-script-restriction",
            "CSP does not restrict scripts",
            "The policy has no script-src or default-src, so scripts are unrestricted.",
            Severity.MEDIUM,
            "Add script-src (or default-src) with specific sources, nonces or hashes.",
        )
    else:
        trusted = any(t.startswith(("'nonce-", "'sha")) for t in scripts)
        if (
            "'unsafe-inline'" in scripts
            and not trusted
            and "'strict-dynamic'" not in scripts
        ):
            _add(
                issues,
                "unsafe-inline",
                "CSP allows unsafe-inline scripts",
                "script-src has 'unsafe-inline' without a nonce or hash.",
                Severity.MEDIUM,
                "Remove 'unsafe-inline'; use nonces or hashes for inline scripts.",
            )
        if "'unsafe-eval'" in scripts:
            _add(
                issues,
                "unsafe-eval",
                "CSP allows unsafe-eval",
                "script-src has 'unsafe-eval', which permits eval() and similar APIs.",
                Severity.MEDIUM,
                "Remove 'unsafe-eval' and refactor code that needs eval().",
            )
        if "*" in scripts or BROAD_SCHEMES & set(scripts):
            _add(
                issues,
                "wildcard-source",
                "CSP script sources are too broad",
                "script-src allows any origin ('*' or a bare scheme such as https:).",
                Severity.MEDIUM,
                "List the exact script origins instead of a wildcard or bare scheme.",
            )
    if "object-src" not in directives and "default-src" not in directives:
        _add(
            issues,
            "missing-object-src",
            "CSP lacks object-src",
            "Without object-src or default-src, plugin content is not restricted.",
            Severity.LOW,
            "Add object-src 'none'.",
        )
    if "base-uri" not in directives:
        _add(
            issues,
            "missing-base-uri",
            "CSP lacks base-uri",
            "Without base-uri, an injected <base> tag redirects relative URLs.",
            Severity.LOW,
            "Add base-uri 'self' (or 'none').",
        )
    return issues


def hsts_issues(value: str) -> list[PolicyIssue]:
    tokens = [t.strip() for t in value.split(";") if t.strip()]
    max_age = next((int(m.group(1)) for t in tokens if (m := _MAX_AGE.match(t))), None)
    lowered = {t.lower() for t in tokens}
    subdomains, preload = "includesubdomains" in lowered, "preload" in lowered
    issues: list[PolicyIssue] = []

    if max_age is None:
        _add(
            issues,
            "no-max-age",
            "HSTS header has no valid max-age",
            "Browsers ignore a Strict-Transport-Security header without max-age.",
            Severity.MEDIUM,
            "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        )
    elif max_age == 0:
        _add(
            issues,
            "max-age-zero",
            "HSTS is disabled (max-age=0)",
            "max-age=0 tells browsers to forget the HSTS policy.",
            Severity.MEDIUM,
            "Set max-age to at least 31536000.",
        )
    elif max_age < HSTS_MIN_MAX_AGE:
        _add(
            issues,
            "short-max-age",
            f"HSTS max-age is short ({max_age} seconds)",
            f"max-age is below {HSTS_MIN_MAX_AGE} seconds, so protection lapses fast.",
            Severity.LOW,
            "Set max-age to at least 31536000.",
        )
    if not subdomains:
        _add(
            issues,
            "no-include-subdomains",
            "HSTS lacks includeSubDomains",
            "Subdomains are not covered, so they can be downgraded to HTTP.",
            Severity.INFO,
            "Add includeSubDomains once every subdomain serves HTTPS.",
        )
    if preload and (
        not subdomains or max_age is None or max_age < HSTS_PRELOAD_MIN_MAX_AGE
    ):
        _add(
            issues,
            "invalid-preload",
            "HSTS preload directive is not eligible",
            "Preload needs includeSubDomains and max-age of at least 31536000.",
            Severity.LOW,
            "Meet the preload requirements or remove the preload directive.",
        )
    return issues
