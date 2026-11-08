import logging
import sqlite3
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from ..models import ScanSession
from ..models.scan_config_template import ScanConfigTemplate
from .connection import connect
from .findings import FindingRepository
from .migrate import migrate
from .scans import ScanRepository
from .templates import TemplateRepository
from .websites import WebsiteRepository

logger = logging.getLogger(__name__)

__all__ = ["ScanStore"]


class ScanStore:
    def __init__(self, db_path: str | Path = "data/HARIS.db") -> None:
        self.db_path = Path(db_path)
        migrate(self.db_path)
        self._scans = ScanRepository(self.db_path)
        self._findings = FindingRepository(self.db_path)
        self._templates = TemplateRepository(self.db_path)
        self._websites = WebsiteRepository(self.db_path)
        self._templates.seed_defaults()
        logger.debug("Database initialised at %s", self.db_path)

    def _connect(self) -> AbstractContextManager[sqlite3.Connection, bool | None]:
        return connect(self.db_path)

    def save_session(self, session: ScanSession) -> None:
        self._scans.save_session(session)

    def delete_session(self, session_id: str) -> bool:
        return self._scans.delete_session(session_id)

    def list_sessions(self) -> list[dict[str, Any]]:
        return self._scans.list_sessions()

    def load_session(self, session_id: str) -> ScanSession | None:
        return self._scans.load_session(session_id)

    def session_exists(self, session_id: str) -> bool:
        return self._scans.session_exists(session_id)

    def list_sessions_paginated(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        hostname: str | None = None,
        severity: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        template_id: str | None = None,
        scanner: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        return self._scans.list_sessions_paginated(
            page=page,
            per_page=per_page,
            hostname=hostname,
            severity=severity,
            date_from=date_from,
            date_to=date_to,
            template_id=template_id,
            scanner=scanner,
        )

    def get_findings(
        self,
        session_id: str,
        *,
        severity: str | None = None,
        owasp_category: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._findings.get_findings(
            session_id, severity=severity, owasp_category=owasp_category
        )

    def dashboard_summary(self) -> dict[str, Any]:
        return self._websites.dashboard_summary()

    def list_websites(self) -> list[dict[str, Any]]:
        return self._websites.list_websites()

    def get_scans_for_hostname(self, hostname: str) -> list[dict[str, Any]]:
        return self._websites.get_scans_for_hostname(hostname)

    def get_severity_trends(self, hostname: str) -> dict[str, Any]:
        return self._websites.get_severity_trends(hostname)

    def save_scan_config_template(self, tpl: ScanConfigTemplate) -> None:
        self._templates.save(tpl)

    def get_scan_config_template(self, template_id: str) -> ScanConfigTemplate | None:
        return self._templates.get(template_id)

    def list_scan_config_templates(self) -> list[dict[str, Any]]:
        return self._templates.list_all()

    def delete_scan_config_template(self, template_id: str) -> bool:
        return self._templates.delete(template_id)

    def set_default_scan_config_template(self, template_id: str) -> None:
        self._templates.set_default(template_id)

    def get_default_scan_config_template(self) -> ScanConfigTemplate | None:
        return self._templates.get_default()
