import re

from ..models import Severity

# Debug / management endpoints that should never be publicly reachable.
# OpenAPI documents (/api-docs, /v2/api-docs, /v3/api-docs) belong to openapi_checks.
DEBUG_ENDPOINTS: list[tuple[str, str, Severity]] = [
    ("/debug", "Generic debug endpoint", Severity.HIGH),
    ("/trace", "Trace endpoint", Severity.HIGH),
    ("/_debug_toolbar", "Django Debug Toolbar", Severity.HIGH),
    ("/actuator", "Spring Boot Actuator root", Severity.HIGH),
    ("/actuator/env", "Spring Boot Actuator /env", Severity.CRITICAL),
    ("/actuator/dump", "Spring Boot Actuator /dump", Severity.HIGH),
    ("/health", "Health-check endpoint (informational)", Severity.LOW),
    ("/info", "Info endpoint (informational)", Severity.LOW),
    ("/metrics", "Metrics endpoint", Severity.MEDIUM),
    ("/swagger-ui", "Swagger UI", Severity.MEDIUM),
    ("/swagger-ui.html", "Swagger UI (legacy path)", Severity.MEDIUM),
]

# Version-disclosure endpoints
VERSION_ENDPOINTS: list[tuple[str, str]] = [
    ("/version", "Version endpoint"),
    ("/api/version", "API version endpoint"),
    ("/app/version", "App version endpoint"),
]

# Error-page body patterns for stack traces and framework leakage. Case-sensitive;
# framework names need a dotted version so prose ("Express 2024") cannot match.
_VERSION = r"v?\d+\.\d+(?:\.\d+)*"

ERROR_INDICATORS: list[tuple[re.Pattern[str], str, Severity]] = [
    (
        re.compile(r"Traceback \(most recent call last\)"),
        "Python stack trace",
        Severity.HIGH,
    ),
    (
        re.compile(r"\bat\s+[\w.$]+\([\w.]+\.(?:java|kt):\d+\)"),
        "Java/Kotlin stack trace",
        Severity.HIGH,
    ),
    (
        re.compile(r"\bSystem\.Web\.HttpException\b"),
        "ASP.NET exception class",
        Severity.HIGH,
    ),
    (
        re.compile(r"\b(?:Microsoft\.CSharp|System\.Web)\.\w+"),
        ".NET namespace in error response",
        Severity.MEDIUM,
    ),
    (
        re.compile(rf"\bDjango[ /]{_VERSION}"),
        "Django version disclosure",
        Severity.MEDIUM,
    ),
    (
        re.compile(rf"\bLaravel[ /]{_VERSION}"),
        "Laravel version disclosure",
        Severity.MEDIUM,
    ),
    (
        re.compile(rf"\bRuby on Rails[ /]{_VERSION}"),
        "Rails version disclosure",
        Severity.MEDIUM,
    ),
    (
        re.compile(rf"\bExpress[ /]{_VERSION}"),
        "Express.js version disclosure",
        Severity.MEDIUM,
    ),
    (
        re.compile(rf"\bFlask[ /]{_VERSION}"),
        "Flask version disclosure",
        Severity.MEDIUM,
    ),
    (
        re.compile(rf"\bSpring[ /]{_VERSION}"),
        "Spring version disclosure",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"\bDEBUG\s*=\s*True\b"),
        "Django DEBUG=True in response",
        Severity.HIGH,
    ),
    (
        re.compile(r"\bSQLSTATE\["),
        "Raw SQL error / SQLSTATE code",
        Severity.HIGH,
    ),
    (
        re.compile(r"\bORA-\d{5}\b"),
        "Oracle database error code",
        Severity.HIGH,
    ),
    (
        re.compile(r"\bcom\.mysql\.jdbc\.\w+"),
        "MySQL JDBC driver class in response",
        Severity.HIGH,
    ),
    (
        re.compile(
            r"\bCaused by:\s+(?:[a-z_][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error)\b"
        ),
        "Java 'Caused by' exception chain",
        Severity.HIGH,
    ),
    (
        re.compile(r"(?<![\w:/.-])(?:/home/\w+/|/var/www/|/srv/)[\w.-]+"),
        "Internal filesystem path disclosed",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"\b[A-Z]:\\(?:Users|inetpub|Windows)\\"),
        "Windows filesystem path disclosed",
        Severity.MEDIUM,
    ),
]

# HTML comment patterns: (regex, label, severity). Markers are upper-case words;
# credential patterns need an assignment, so plain prose ("hackathon") is ignored.
SENSITIVE_COMMENT_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(r"\bTODO\b"), "TODO comment", Severity.INFO),
    (re.compile(r"\bFIXME\b"), "FIXME comment", Severity.INFO),
    (re.compile(r"\bHACK\b"), "HACK comment", Severity.INFO),
    (
        re.compile(
            r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*\S+"
        ),
        "credential assignment",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
        "private key block",
        Severity.HIGH,
    ),
]

HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
