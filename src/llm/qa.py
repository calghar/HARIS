import json
import logging
from pathlib import Path
from typing import Any

from ..models import Finding, ScanSession
from ..models.chat import ChatMessage
from .base import BaseLLMBackend, LLMResponse
from .prompts import PromptBuilder
from .retriever import FindingRetriever

logger = logging.getLogger(__name__)


class ReportQA:
    """Answer questions about a specific scan report.

    Usage::

        qa = ReportQA(backend=my_llm_backend)
        answer = qa.ask(session, "What are the top 3 risks?")
        print(answer.text)
    """

    def __init__(self, backend: BaseLLMBackend) -> None:
        self.backend = backend
        self._builder = PromptBuilder()

    def ask(
        self,
        session: ScanSession,
        question: str,
        *,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        """Answer a freeform question about a scan report."""
        system, prompt = self._builder.freeform_question(session, question)
        return self.backend.complete(
            prompt,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def summarize(
        self,
        session: ScanSession,
        *,
        audience: str = "executive",
        temperature: float = 0.2,
    ) -> LLMResponse:
        """Generate a report summary for the specified audience."""
        system, prompt = self._builder.summarize_report(session, audience)
        return self.backend.complete(
            prompt, system=system, temperature=temperature
        )

    def explain_finding(
        self,
        session: ScanSession,
        finding_id: str,
        *,
        audience: str = "executive",
    ) -> LLMResponse:
        """Explain a specific finding by its ID."""
        finding = self._find_by_id(session, finding_id)
        if finding is None:
            return LLMResponse(
                text=f"Finding '{finding_id}' not found in this scan."
            )
        system, prompt = self._builder.explain_finding(
            finding, session, audience
        )
        return self.backend.complete(prompt, system=system)

    def remediation_plan(
        self,
        session: ScanSession,
        *,
        format: str = "markdown",
    ) -> LLMResponse:
        """Generate a remediation plan in the specified format."""
        system, prompt = self._builder.propose_remediation_plan(
            session, format
        )
        return self.backend.complete(prompt, system=system)

    def filter_findings(
        self,
        session: ScanSession,
        criteria: str,
    ) -> LLMResponse:
        """Filter and explain findings matching a natural-language query."""
        system, prompt = self._builder.filter_and_explain(session, criteria)
        return self.backend.complete(prompt, system=system)

    def generate_test_cases(
        self,
        session: ScanSession,
        *,
        framework: str = "generic",
    ) -> LLMResponse:
        """Generate CI security test cases from findings."""
        system, prompt = self._builder.generate_test_cases(
            session, framework
        )
        return self.backend.complete(prompt, system=system)

    def suggest_mitigations(
        self,
        session: ScanSession,
        *,
        stack: str = "generic web",
    ) -> LLMResponse:
        """Suggest code-level mitigations for findings."""
        system, prompt = self._builder.suggest_mitigations(session, stack)
        return self.backend.complete(prompt, system=system)

    def chat(
        self,
        session: ScanSession,
        question: str,
        history: list[ChatMessage],
        *,
        max_history_messages: int = 12,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        """Multi-turn Q&A with conversation history."""
        system = self._builder.system_prompt()
        messages = self._build_chat_messages(
            session, history, question, max_history_messages
        )
        return self.backend.complete_messages(
            messages,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    _RETRIEVAL_THRESHOLD = 15

    @classmethod
    def _build_chat_messages(
        cls,
        session: ScanSession,
        history: list[ChatMessage],
        question: str,
        max_history: int,
    ) -> list[dict[str, str]]:
        """Build a messages list with context, history, and new question.

        When findings exceed the retrieval threshold, uses FTS5 to
        select only the most relevant findings for the context,
        significantly reducing token usage.
        """
        if len(session.all_findings) > cls._RETRIEVAL_THRESHOLD:
            retriever = FindingRetriever(session.all_findings)
            try:
                relevant = retriever.retrieve(question, top_k=10)
            finally:
                retriever.close()
            context = PromptBuilder._format_selective_context(
                session, relevant
            )
        else:
            context = PromptBuilder._format_session_context(session)

        context_msg = (
            "Here is the scan report context:\n\n" + context
        )
        ack_msg = (
            "I've reviewed the scan report. "
            "What would you like to know?"
        )
        messages: list[dict[str, str]] = [
            {"role": "user", "content": context_msg},
            {"role": "assistant", "content": ack_msg},
        ]
        # Append recent history (trim oldest if over limit)
        recent = (
            history[-max_history:]
            if len(history) > max_history
            else history
        )
        for msg in recent:
            messages.append(
                {"role": msg.role, "content": msg.content}
            )
        # Append the new question
        messages.append({"role": "user", "content": question})
        return messages

    def draft_email(
        self,
        session: ScanSession,
    ) -> LLMResponse:
        """Draft an email summarising the risk posture."""
        system, prompt = self._builder.propose_remediation_plan(
            session, format="email"
        )
        return self.backend.complete(prompt, system=system)

    @staticmethod
    def _find_by_id(
        session: ScanSession, finding_id: str
    ) -> Finding | None:
        """Look up a finding by ID within a session."""
        for f in session.all_findings:
            if f.finding_id == finding_id:
                return f
        return None

    @classmethod
    def from_json_file(
        cls,
        report_path: str | Path,
        backend: BaseLLMBackend,
    ) -> tuple["ReportQA", ScanSession]:
        """Load a scan session from a JSON report file.

        Returns a (ReportQA, ScanSession) tuple ready for querying.
        """
        path = Path(report_path)
        raw = json.loads(path.read_text(encoding="utf-8"))

        findings = [
            Finding.from_dict(f) for f in raw.get("findings", [])
        ]

        from ..models import RiskPosture, ScanSession

        meta = raw.get("meta", {})
        risk_raw = raw.get("risk_posture", {})

        session = ScanSession(
            session_id=meta.get("session_id", "unknown"),
            target=_build_target_from_meta(meta),
            started_at=meta.get("started_at", ""),
            finished_at=meta.get("finished_at", ""),
            profile_name=meta.get("profile", ""),
            scanners_used=meta.get("scanners_used", []),
            all_findings=findings,
            risk_posture=RiskPosture(risk_raw.get("level", "moderate")),
            risk_posture_text=risk_raw.get("description", ""),
        )

        return cls(backend=backend), session


    @classmethod
    def from_db(
        cls,
        session_id: str,
        backend: BaseLLMBackend,
        db_path: str | Path = "data/HARIS.db",
    ) -> tuple["ReportQA", ScanSession]:
        """Load a scan session from the SQLite database.

        Returns a (ReportQA, ScanSession) tuple ready for querying.
        Raises ValueError if the session is not found.
        """
        from ..db.store import ScanStore

        store = ScanStore(db_path)
        session = store.load_session(session_id)
        if session is None:
            raise ValueError(f"Session '{session_id}' not found in database.")
        return cls(backend=backend), session


def _build_target_from_meta(meta: dict[str, Any]) -> Any:
    """Reconstruct a minimal Target from report metadata."""
    from ..models import Target

    return Target(base_url=meta.get("target", "https://unknown"))
