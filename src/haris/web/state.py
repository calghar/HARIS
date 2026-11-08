from collections.abc import Callable

from fastapi import Request

from ..auth.api_tokens import ApiTokenService
from ..auth.service import AuthService
from ..db.jobs import Job, JobStatus
from ..db.store import ScanStore
from .conversations import ConversationRegistry
from .job_queue import CancelToken, JobQueue
from .settings import WebSettings
from .targets import TargetAuthoriser


class AppState:
    """Per-application services, reachable as `app.state.haris`."""

    def __init__(
        self,
        settings: WebSettings,
        execute: Callable[["AppState", Job, CancelToken], JobStatus],
    ) -> None:
        self.settings = settings
        self.store = ScanStore(settings.db_path)
        self.auth = AuthService(settings.db_path)
        self.tokens = ApiTokenService(self.store.api_tokens)
        self.targets = TargetAuthoriser(self.store.targets, settings.target_allowlist)
        self.conversations = ConversationRegistry()
        # Target credentials stay in memory only; queued jobs keep none on disk.
        self.scan_credentials: dict[str, str] = {}
        self.jobs = JobQueue(
            self.store.jobs,
            lambda job, token: execute(self, job, token),
            settings.max_concurrent_scans,
        )


def get_state(request: Request) -> AppState:
    state: AppState = request.app.state.haris
    return state
