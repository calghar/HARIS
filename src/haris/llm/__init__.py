"""LLM adapter layer for AI-powered report analysis.

Provides an abstract interface for LLM backends and a set of
high-level operations (summarise, explain, plan remediation) that
transform structured scan data into prompts and parse responses.

All LLM features are optional and can be disabled entirely via
configuration.
"""

from .base import BaseLLMBackend, LLMResponse
from .correlation import LLMCorrelator
from .enrichment import FindingEnricher
from .prompts import PromptBuilder
from .qa import ReportQA
from .triage import SmartTriager
from .variant_analysis import VariantAnalyzer

__all__ = [
    "BaseLLMBackend",
    "FindingEnricher",
    "LLMCorrelator",
    "LLMResponse",
    "PromptBuilder",
    "ReportQA",
    "SmartTriager",
    "VariantAnalyzer",
]
