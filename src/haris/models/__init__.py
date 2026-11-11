"""Pydantic data models for the HARIS framework.

All data models (enums, value objects, configuration) live here.
Business logic (scanners, engine, correlators, planners) stays
in their respective packages (src/haris/core, src/haris/scanners, etc.).
"""

from .chat import ChatMessage, Conversation
from .config import Config, LLMConfig, ScannerConfig
from .correlator import CorrelatedFinding
from .enrichment import (
    AttackChain,
    EnrichedFinding,
    EnrichmentContext,
    TriageContext,
    TriagedFinding,
)
from .enums import (
    Confidence,
    Effort,
    OwaspCategory,
    RiskPosture,
    ScanState,
    Severity,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
    confidence_from_score,
)
from .finding import Finding
from .llm import LLMResponse
from .owasp import OwaspMapping
from .profiles import ScanProfile
from .remediation import RemediationStep
from .risk import BusinessImpact
from .scan_config_template import ScanConfigTemplate
from .scan_context import ScanContext
from .scanner import ScannerResult
from .session import ScanSession
from .target import AuthConfig, Scope, Target
from .templates import TemplateConfig, TemplateMetadata, TemplateSource, UpdateResult
from .verification import EvidenceExchange, LLMAssessment, Suppression, Verification

__all__ = [
    # Enums
    "Confidence",
    "Effort",
    "OwaspCategory",
    "RiskPosture",
    "ScanState",
    "Severity",
    "VerificationMethod",
    "VerificationOracle",
    "VerificationTier",
    "confidence_from_score",
    # Models
    "ChatMessage",
    "Conversation",
    "AttackChain",
    "AuthConfig",
    "BusinessImpact",
    "Config",
    "LLMConfig",
    "CorrelatedFinding",
    "EnrichedFinding",
    "EnrichmentContext",
    "EvidenceExchange",
    "Finding",
    "LLMAssessment",
    "LLMResponse",
    "OwaspMapping",
    "RemediationStep",
    "ScanConfigTemplate",
    "ScanContext",
    "ScannerConfig",
    "ScannerResult",
    "ScanProfile",
    "ScanSession",
    "Scope",
    "Suppression",
    "Target",
    "TriageContext",
    "TriagedFinding",
    "TemplateConfig",
    "TemplateMetadata",
    "TemplateSource",
    "UpdateResult",
    "Verification",
]
