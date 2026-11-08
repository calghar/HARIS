from itertools import count
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from haris.auth.cookies import SESSION_COOKIE
from haris.auth.csrf import make_token
from haris.auth.middleware import _login_attempts
from haris.auth.models import User, UserRole
from haris.auth.tokens import hash_token
from haris.models import ScanSession, Target
from haris.models.chat import Conversation
from haris.models.scan_config_template import ScanConfigTemplate
from haris.web.app import create_app
from haris.web.ownership import SCAN, TEMPLATE
from haris.web.settings import WebSettings
from haris.web.state import AppState

PASSWORD = "correct-horse-battery"

_ids = count(1)


class Browser(TestClient):
    """Test client with a session cookie and the matching CSRF token."""

    csrf: str = ""

    def __init__(self, app: FastAPI) -> None:
        super().__init__(app, follow_redirects=False, raise_server_exceptions=False)

    @property
    def csrf_headers(self) -> dict[str, str]:
        return {"X-CSRF-Token": self.csrf}


class WebEnv:
    """App on a temporary database with an admin and two ordinary users."""

    def __init__(
        self, tmp_path: Path, *, share_scans: bool = False, seed_users: bool = True
    ) -> None:
        self.settings = WebSettings(
            db_path=tmp_path / "web.db",
            reports_dir=tmp_path / "reports",
            log_dir=tmp_path / "logs",
            secret_key="test-secret-key",
            share_scans_org_wide=share_scans,
        )
        self.app: FastAPI = create_app(self.settings)
        self.state: AppState = self.app.state.haris
        _login_attempts.clear()
        self.admin: User
        self.alice: User
        self.bob: User
        if not seed_users:
            return
        self.admin = self.state.auth.create_user(
            "admin@example.com", PASSWORD, role=UserRole.ADMIN
        )
        self.alice = self.state.auth.create_user("alice@example.com", PASSWORD)
        self.bob = self.state.auth.create_user("bob@example.com", PASSWORD)
        self.add_scan(self.alice)

    def anonymous(self) -> Browser:
        return Browser(self.app)

    def browser(self, user: User) -> Browser:
        token = self.state.auth.create_session(user.user_id).token
        client = Browser(self.app)
        client.cookies.set(SESSION_COOKIE, token)
        client.csrf = make_token(self.settings.secret_key, token)
        return client

    def add_scan(
        self, owner: User | None, *, url: str = "https://app.example.com"
    ) -> str:
        scan_id = f"scan{next(_ids):04d}"
        self.state.store.save_session(
            ScanSession(
                session_id=scan_id,
                target=Target(base_url=url),
                started_at="2026-01-02T03:04:05+00:00",
                finished_at="2026-01-02T03:09:05+00:00",
                profile_name="quick",
            )
        )
        if owner:
            self.state.owners.assign(SCAN, scan_id, owner.user_id)
        return scan_id

    def add_template(self, owner: User | None) -> str:
        template = ScanConfigTemplate(name=f"tpl-{next(_ids)}")
        self.state.store.save_scan_config_template(template)
        if owner:
            self.state.owners.assign(TEMPLATE, template.template_id, owner.user_id)
        return template.template_id

    def add_conversation(self, owner: User, scan_id: str) -> str:
        conversation = Conversation(
            conversation_id=f"conv{next(_ids):04d}",
            scan_id=scan_id,
            backend_name="none",
        )
        self.state.conversations.add(conversation, owner.user_id)
        return conversation.conversation_id

    def resources(self, owner: User, actor: User | None = None) -> "Resources":
        return Resources(self, owner, actor or owner)


class Resources(dict[str, str]):
    """Path parameters created on first use, so each request gets fresh ones."""

    def __init__(self, env: WebEnv, owner: User, actor: User) -> None:
        super().__init__(hostname="app.example.com", fmt="json", finding_id="none")
        self._env = env
        self._owner = owner
        self._actor = actor

    def __missing__(self, key: str) -> str:
        env, owner = self._env, self._owner
        if key == "scan_id":
            value = env.add_scan(owner)
        elif key == "template_id":
            value = env.add_template(owner)
        elif key == "conversation_id":
            value = env.add_conversation(owner, self["scan_id"])
        elif key == "user_id":
            value = env.state.auth.create_user(
                f"v{next(_ids)}@example.com", PASSWORD
            ).user_id
        elif key == "token":
            value = hash_token(env.state.auth.create_session(self._actor.user_id).token)
        else:
            raise KeyError(key)
        self[key] = value
        return value


def stub_scan_runner(patch: pytest.MonkeyPatch) -> None:
    """Scans started through the API must not launch real scanners."""
    patch.setattr("haris.web.routers.scans.run_scan_blocking", lambda *a, **k: None)
