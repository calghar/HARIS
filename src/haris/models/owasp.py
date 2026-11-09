from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from .enums import OwaspCategory


class OwaspMapping(BaseModel):
    """Maps a CWE or vulnerability keyword to an OWASP 2025 category."""

    model_config = ConfigDict(frozen=True)

    category: OwaspCategory
    description: str
    typical_cwes: tuple[str, ...]


# Checked at genai.owasp.org/llm-top-10 on 2026-11-08; a 2026 edition renumbers it.
class LlmRisk(StrEnum):
    """OWASP Top 10 for LLM Applications 2025."""

    LLM01 = "LLM01:2025 - Prompt Injection"
    LLM02 = "LLM02:2025 - Sensitive Information Disclosure"
    LLM03 = "LLM03:2025 - Supply Chain"
    LLM04 = "LLM04:2025 - Data and Model Poisoning"
    LLM05 = "LLM05:2025 - Improper Output Handling"
    LLM06 = "LLM06:2025 - Excessive Agency"
    LLM07 = "LLM07:2025 - System Prompt Leakage"
    LLM08 = "LLM08:2025 - Vector and Embedding Weaknesses"
    LLM09 = "LLM09:2025 - Misinformation"
    LLM10 = "LLM10:2025 - Unbounded Consumption"


# Checked in the official PDF, genai.owasp.org/download/52117 (December 2025).
class AgenticRisk(StrEnum):
    """OWASP Top 10 for Agentic Applications 2026."""

    ASI01 = "ASI01 - Agent Goal Hijack"
    ASI02 = "ASI02 - Tool Misuse and Exploitation"
    ASI03 = "ASI03 - Identity and Privilege Abuse"
    ASI04 = "ASI04 - Agentic Supply Chain Vulnerabilities"
    ASI05 = "ASI05 - Unexpected Code Execution (RCE)"
    ASI06 = "ASI06 - Memory & Context Poisoning"
    ASI07 = "ASI07 - Insecure Inter-Agent Communication"
    ASI08 = "ASI08 - Cascading Failures"
    ASI09 = "ASI09 - Human-Agent Trust Exploitation"
    ASI10 = "ASI10 - Rogue Agents"


# Checked at owasp.org/www-project-mcp-top-10 on 2026-11-08; the page says beta.
# [UNVERIFIED] OWASP project level and whether these ids survive the final release.
class McpRisk(StrEnum):
    """OWASP MCP Top 10 2025 (beta)."""

    MCP01 = "MCP01:2025 - Token Mismanagement & Secret Exposure"
    MCP02 = "MCP02:2025 - Privilege Escalation via Scope Creep"
    MCP03 = "MCP03:2025 - Tool Poisoning"
    MCP04 = "MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering"
    MCP05 = "MCP05:2025 - Command Injection & Execution"
    MCP06 = "MCP06:2025 - Prompt Injection via Contextual Payloads"
    MCP07 = "MCP07:2025 - Insufficient Authentication & Authorization"
    MCP08 = "MCP08:2025 - Lack of Audit and Telemetry"
    MCP09 = "MCP09:2025 - Shadow MCP Servers"
    MCP10 = "MCP10:2025 - Context Injection & Over-Sharing"


type AiRisk = LlmRisk | AgenticRisk | McpRisk
