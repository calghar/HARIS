import threading
import time
from collections.abc import Callable
from itertools import count
from pathlib import Path
from typing import Any

import pytest
import requests
from fastapi import FastAPI
from fastapi.testclient import TestClient

from haris.auth.cookies import SESSION_COOKIE
from haris.auth.csrf import make_token
from haris.auth.middleware import _login_attempts
from haris.auth.models import User, UserRole
from haris.auth.tokens import hash_token
from haris.db.connection import connect
from haris.db.jobs import Job, JobStatus
from haris.models import ScanSession, ScanState, Target
from haris.models.chat import Conversation
from haris.models.scan_config_template import ScanConfigTemplate
from haris.net import NetworkPolicy, ScopedClient
from haris.web.app import create_app
from haris.web.job_queue import CancelToken
from haris.web.settings import WebSettings
from haris.web.state import AppState
from haris.web.targets import TargetAuthoriser

from .fake_transport import FakeAdapter, Handler, Reply

PASSWORD = "correct-horse-battery"
PUBLIC_ADDRESS = "93.184.216.34"
RUNNER_WAIT_S = 30.0
POLL_S = 0.01

_ids = count(1)


class Browser(TestClient):
    """Test client with a session cookie and the matching CSRF token."""

    csrf: str = ""
    token: str = ""
    token_id: str = ""

    def __init__(self, app: FastAPI) -> None:
        super().__init__(app, follow_redirects=False, raise_server_exceptions=False)

    @property
    def csrf_headers(self) -> dict[str, str]:
        return {"X-CSRF-Token": self.csrf}


class WebEnv:
    """App on a temporary database with an admin and two ordinary users."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        share_scans: bool = False,
        seed_users: bool = True,
        allowlist: list[str] | None = None,
        max_concurrent: int = 2,
    ) -> None:
        self.settings = WebSettings(
            db_path=tmp_path / "web.db",
            reports_dir=tmp_path / "reports",
            log_dir=tmp_path / "logs",
            secret_key="test-secret-key",
            share_scans_org_wide=share_scans,
            target_allowlist=["*.example.com"] if allowlist is None else allowlist,
            max_concurrent_scans=max_concurrent,
        )
        self.resolves: dict[str, list[str]] = {}
        self.proof_requests: list[requests.PreparedRequest] = []
        self.proof_handler: Handler = lambda _request: (404, {}, b"")
        self.app: FastAPI = create_app(self.settings)
        self.state: AppState = self.app.state.haris
        self.use_targets()
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

    def _resolve(self, host: str, _port: int) -> list[str]:
        return self.resolves.get(host, [PUBLIC_ADDRESS])

    def _proof_client(self, target: Target, policy: NetworkPolicy) -> ScopedClient:
        def reply(request: requests.PreparedRequest) -> Reply:
            self.proof_requests.append(request)
            return self.proof_handler(request)

        return ScopedClient(
            target,
            policy,
            resolver=self._resolve,
            adapter_factory=lambda _host: FakeAdapter(reply),
        )

    def use_targets(self, **overrides: Any) -> None:
        """Replace the target authoriser; DNS and HTTP never leave the process."""
        options: dict[str, Any] = {
            "resolver": self._resolve,
            "txt_lookup": lambda name: [],
            "client_factory": self._proof_client,
        }
        self.state.targets = TargetAuthoriser(
            self.state.store.targets,
            self.settings.target_allowlist,
            **(options | overrides),
        )

    def anonymous(self) -> Browser:
        return Browser(self.app)

    def browser(self, user: User) -> Browser:
        token = self.state.auth.create_session(user.user_id).token
        client = Browser(self.app)
        client.cookies.set(SESSION_COOKIE, token)
        client.csrf = make_token(self.settings.secret_key, token)
        return client

    def bearer(self, user: User, scopes: tuple[str, ...] = ("scans:read",)) -> Browser:
        """Client that authenticates with a fresh API token and no cookie."""
        record, token = self.state.tokens.create(user.user_id, "test", list(scopes))
        client = Browser(self.app)
        client.headers["Authorization"] = f"Bearer {token}"
        client.token, client.token_id = token, record.token_id
        return client

    def expire_token(self, token_id: str) -> None:
        with connect(self.settings.db_path) as conn:
            conn.execute(
                "UPDATE api_tokens SET expires_at = '2000-01-01T00:00:00+00:00'"
                " WHERE token_id = ?",
                (token_id,),
            )

    def add_scan(
        self,
        owner: User | None,
        *,
        url: str = "https://app.example.com",
        state: ScanState = ScanState.COMPLETED,
        errors: list[str] | None = None,
    ) -> str:
        scan_id = f"scan{next(_ids):04d}"
        self.state.store.save_session(
            ScanSession(
                session_id=scan_id,
                target=Target(base_url=url),
                started_at="2026-01-02T03:04:05+00:00",
                finished_at="2026-01-02T03:09:05+00:00",
                profile_name="quick",
                scan_state=state,
                errors=errors or [],
            ),
            owner_user_id=owner.user_id if owner else "",
        )
        return scan_id

    def add_template(self, owner: User | None) -> str:
        template = ScanConfigTemplate(name=f"tpl-{next(_ids)}")
        self.state.store.save_scan_config_template(
            template, owner_user_id=owner.user_id if owner else ""
        )
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
        elif key == "host":
            value = env.state.targets.issue(
                self._actor.user_id, f"t{next(_ids)}.example.com"
            ).host
        elif key == "token_id":
            value = env.state.tokens.create(self._actor.user_id, "t", ["scans:read"])[
                0
            ].token_id
        elif key == "token":
            value = hash_token(env.state.auth.create_session(self._actor.user_id).token)
        else:
            raise KeyError(key)
        self[key] = value
        return value


class FakeRunner:
    """Stands in for `execute_scan`: reports a fixed status without scanning."""

    def __init__(self, *, block: bool = False) -> None:
        self.status = JobStatus.COMPLETED
        self.error = ""
        self.started: list[str] = []
        self.active = 0
        self.peak = 0
        self._lock = threading.Lock()
        self._release = threading.Event()
        if not block:
            self._release.set()

    def release(self) -> None:
        self._release.set()

    def wait_started(self, count: int = 1) -> None:
        wait_for(lambda: len(self.started) >= count)

    def __call__(self, state: AppState, job: Job, token: CancelToken) -> JobStatus:
        with self._lock:
            self.started.append(job.scan_id)
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            deadline = time.monotonic() + RUNNER_WAIT_S
            while not (self._release.is_set() or token.cancelled):
                if time.monotonic() > deadline:
                    break
                time.sleep(POLL_S)
            if self.error:
                raise RuntimeError(self.error)
            return JobStatus.CANCELLED if token.cancelled else self.status
        finally:
            with self._lock:
                self.active -= 1


def wait_for(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + RUNNER_WAIT_S
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        time.sleep(POLL_S)


def stub_scan_runner(patch: pytest.MonkeyPatch, *, block: bool = False) -> FakeRunner:
    """Scans started through the API must not launch real scanners."""
    runner = FakeRunner(block=block)
    patch.setattr("haris.web.scan_runtime.execute_scan", runner)
    return runner
