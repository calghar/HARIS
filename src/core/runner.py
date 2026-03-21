import contextlib
import logging
from typing import Any

from ..config.loader import load_config
from ..models import Config, ScanSession, Target
from .decorators import all_registered
from .engine import ScanEngine
from .profiles import get_profile

logger = logging.getLogger(__name__)


class ScanRunner:
    """High-level scan orchestrator that wires up scanners, templates, and LLM.

    Both the CLI (``scripts/run_scan.py``) and the web dashboard
    (``src/web/app.py``) delegate to this class so behaviour stays consistent.
    """

    def __init__(
        self,
        target: Target,
        profile_name: str = "full",
        config: Config | None = None,
        session_id: str | None = None,
        scanner_names: list[str] | None = None,
        llm_enrich: bool = False,
        llm_backend_name: str | None = None,
        scanner_options: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._target = target
        self._profile_name = profile_name
        self._config = config or load_config()
        self._session_id = session_id
        self._scanner_names = scanner_names
        self._llm_enrich = llm_enrich
        self._llm_backend_name = llm_backend_name
        self._scanner_options = scanner_options or {}

    def run(self) -> ScanSession:
        """Execute the full scan pipeline and return the session."""
        scanner_instances = self._build_scanners()
        if not scanner_instances:
            raise RuntimeError("No scanners available for this configuration")

        template_manager = self._create_template_manager()
        llm_backend, llm_config = self._create_llm_enrichment()

        kwargs: dict[str, Any] = {"scanners": scanner_instances}
        if self._session_id:
            kwargs["session_id"] = self._session_id
        if template_manager:
            kwargs["template_manager"] = template_manager
        if llm_backend:
            kwargs["llm_backend"] = llm_backend
            kwargs["llm_config"] = llm_config

        engine = ScanEngine(**kwargs)
        session = engine.run(self._target)

        profile = None
        with contextlib.suppress(KeyError):
            profile = get_profile(self._profile_name)
        if profile:
            session.profile_name = profile.display_name
            session.profile_intro = profile.report_intro

        return session

    def _build_scanners(self) -> list[Any]:
        registered = all_registered()

        if self._scanner_names:
            names = self._scanner_names
        else:
            profile = None
            with contextlib.suppress(KeyError):
                profile = get_profile(self._profile_name)
            if profile:
                names = profile.scanners
            else:
                names = [s.name for s in self._config.enabled_scanners]

        instances = []
        for name in names:
            cls = registered.get(name)
            if cls is None:
                logger.warning("Unknown scanner: %s — skipping", name)
                continue
            # Merge order: config defaults → template overrides
            options: dict[str, Any] = {}
            for sc in self._config.scanners:
                if sc.name == name:
                    options = dict(sc.options)
                    break
            if name in self._scanner_options:
                options.update(self._scanner_options[name])
            instances.append(cls(options=options))

        return instances

    def _create_template_manager(self) -> Any:
        if not self._config.template_sources:
            return None
        try:
            from ..templates.manager import TemplateManager

            return TemplateManager(
                base_dir=self._config.template_dir,
                sources=self._config.template_sources,
            )
        except Exception as exc:
            logger.warning("Could not initialise template manager: %s", exc)
            return None

    def _create_llm_enrichment(self) -> tuple[Any, dict[str, Any]]:
        if not (self._llm_enrich or self._config.llm.enrichment_enabled):
            return None, {}
        try:
            from ..llm.base import create_backend

            backend_name = self._llm_backend_name or self._config.llm.backend
            model_kwargs: dict[str, Any] = {}
            if self._config.llm.model:
                model_kwargs["model"] = self._config.llm.model
            llm_backend = create_backend(backend_name, **model_kwargs)
            llm_config = {
                "enrichment_enabled": True,
                "enrich_severity_threshold": self._config.llm.enrich_severity_threshold,
                "max_tokens_per_finding": self._config.llm.max_tokens_per_finding,
                "triage_context": self._config.llm.triage_context,
                "model_routing": self._config.llm.model_routing,
            }
            return llm_backend, llm_config
        except Exception as exc:
            logger.warning("Could not initialise LLM backend: %s", exc)
            return None, {}


def build_scan_list(
    memory_scans: dict[str, dict[str, Any]],
    store: Any,
) -> list[dict[str, Any]]:
    """Merge in-memory active scans with persisted DB scans.

    Returns a list of scan dicts sorted by start time (newest first).
    """
    seen_ids: set[str] = set()
    results: list[dict[str, Any]] = []

    for scan in memory_scans.values():
        seen_ids.add(scan["scan_id"])
        session: ScanSession | None = scan.get("session")
        results.append(
            {
                "scan_id": scan["scan_id"],
                "target_url": scan["target_url"],
                "profile": scan.get("profile", ""),
                "status": scan["status"],
                "started_at": scan.get("started_at", ""),
                "finished_at": scan.get("finished_at"),
                "risk_posture": session.risk_posture.value if session else None,
                "total_findings": len(session.all_findings) if session else 0,
                "error": scan.get("error"),
            }
        )

    try:
        for row in store.list_sessions():
            if row["session_id"] not in seen_ids:
                results.append(
                    {
                        "scan_id": row["session_id"],
                        "target_url": row["target_url"],
                        "profile": row["profile_name"],
                        "status": "completed",
                        "started_at": row["started_at"],
                        "finished_at": None,
                        "risk_posture": row["risk_posture"],
                        "total_findings": row["finding_count"],
                        "error": None,
                    }
                )
    except Exception as exc:
        logger.warning("Could not load scan history from database: %s", exc)

    results.sort(key=lambda s: s.get("started_at", ""), reverse=True)
    return results
