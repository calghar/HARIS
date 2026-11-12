"""Enumerations used across the HARIS data models.

All enums use :class:`enum.StrEnum` (Python 3.11+) so that
``member == member.value`` holds true and ``.value`` access is
no longer required for string comparisons or serialisation.
"""

import enum

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class Severity(enum.StrEnum):
    """CVSS-aligned severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def sort_key(self) -> int:
        return _SEVERITY_ORDER[self.value]


class Confidence(enum.StrEnum):
    """How confident we are that this is a true positive."""

    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"


def confidence_from_score(score: float) -> Confidence:
    """Derive the confidence enum from a numeric score."""
    if score >= 0.9:
        return Confidence.CONFIRMED
    if score >= 0.6:
        return Confidence.FIRM
    return Confidence.TENTATIVE


_TIER_RANK: dict[str, int] = {
    "exploit_validated": 3,
    "replay_verified": 2,
    "unverified": 1,
    "refuted": 0,
}


class VerificationTier(enum.StrEnum):
    """How far a finding has been verified; never changes its fingerprint."""

    UNVERIFIED = "unverified"
    REPLAY_VERIFIED = "replay_verified"
    EXPLOIT_VALIDATED = "exploit_validated"
    REFUTED = "refuted"

    @property
    def rank(self) -> int:
        """Higher is stronger; picks the canonical finding of a bucket."""
        return _TIER_RANK[self.value]


class VerificationMethod(enum.StrEnum):
    NONE = "none"
    REPLAY = "replay"
    AGENT = "agent"


class VerificationOracle(enum.StrEnum):
    NONE = "none"
    REFLECTION = "reflection"
    ERROR_SIGNATURE = "error_signature"
    TIMING = "timing"
    HEADER_PRESENCE = "header_presence"
    CONTENT_VALIDATOR = "content_validator"
    SOFT404 = "soft404"
    CANARY = "canary"
    PATH_TRAVERSAL = "path_traversal"
    OPEN_REDIRECT = "open_redirect"
    TIMING_CMD = "timing_cmd"


class ScanState(enum.StrEnum):
    """Lifecycle state of a scan; drives the CLI exit code."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScannerStatus(enum.StrEnum):
    """Per-scanner outcome; the last two are set by a scanner in its metadata."""

    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"


class OwaspCategory(enum.StrEnum):
    """OWASP Top 10 2025 categories."""

    A01_BROKEN_ACCESS_CONTROL = "A01:2025 - Broken Access Control"
    A02_SECURITY_MISCONFIGURATION = "A02:2025 - Security Misconfiguration"
    A03_SUPPLY_CHAIN_FAILURES = "A03:2025 - Software Supply Chain Failures"
    A04_CRYPTOGRAPHIC_FAILURES = "A04:2025 - Cryptographic Failures"
    A05_INJECTION = "A05:2025 - Injection"
    A06_INSECURE_DESIGN = "A06:2025 - Insecure Design"
    A07_AUTH_FAILURES = "A07:2025 - Authentication Failures"
    A08_INTEGRITY_FAILURES = "A08:2025 - Software or Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2025 - Security Logging and Alerting Failures"
    A10_EXCEPTIONAL_CONDITIONS = "A10:2025 - Mishandling of Exceptional Conditions"


class Effort(enum.StrEnum):
    """Estimated implementation effort for a remediation step."""

    QUICK_WIN = "quick_win"
    MODERATE = "moderate"
    SIGNIFICANT = "significant"


class RiskPosture(enum.StrEnum):
    """Overall risk posture for the target."""

    CRITICAL = "critical"
    POOR = "poor"
    MODERATE = "moderate"
    GOOD = "good"
    EXCELLENT = "excellent"
    UNKNOWN = "unknown"
