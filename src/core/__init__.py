"""Core abstractions for the HARIS framework."""

from ..models import (
    AuthConfig,
    BusinessImpact,
    Confidence,
    CorrelatedFinding,
    Effort,
    Finding,
    LLMResponse,
    OwaspCategory,
    OwaspMapping,
    RemediationStep,
    RiskPosture,
    ScannerConfig,
    ScannerResult,
    ScanProfile,
    ScanSession,
    Scope,
    Severity,
    Target,
)
from .context import http_session, scan_context, temp_workspace
from .correlator import FindingCorrelator
from .decorators import (
    handle_scanner_errors,
    register_check,
    register_scanner,
    timed,
)
from .engine import ScanEngine
from .owasp import all_categories, map_cwe_to_owasp, map_to_owasp
from .profiles import get_profile, list_profiles
from .remediation import RemediationPlanner
from .risk import assess_risk_posture, get_business_impact
from .scanner import BaseScanner

__all__ = [
    "AuthConfig",
    "BaseScanner",
    "BusinessImpact",
    "Confidence",
    "CorrelatedFinding",
    "Effort",
    "Finding",
    "FindingCorrelator",
    "LLMResponse",
    "OwaspCategory",
    "OwaspMapping",
    "RemediationPlanner",
    "RemediationStep",
    "RiskPosture",
    "ScanEngine",
    "ScannerConfig",
    "ScannerResult",
    "ScanProfile",
    "ScanSession",
    "Scope",
    "Severity",
    "Target",
    "all_categories",
    "assess_risk_posture",
    "get_business_impact",
    "get_profile",
    "handle_scanner_errors",
    "http_session",
    "list_profiles",
    "map_cwe_to_owasp",
    "map_to_owasp",
    "register_check",
    "register_scanner",
    "scan_context",
    "temp_workspace",
    "timed",
]
