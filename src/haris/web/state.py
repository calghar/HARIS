from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import Request

from ..auth.service import AuthService
from ..db.store import ScanStore
from .conversations import ConversationRegistry
from .ownership import ResourceOwners
from .settings import WebSettings

SCAN_WORKERS = 2


class AppState:
    """Per-application services, reachable as `app.state.haris`."""

    def __init__(self, settings: WebSettings) -> None:
        self.settings = settings
        self.store = ScanStore(settings.db_path)
        self.auth = AuthService(settings.db_path)
        self.owners = ResourceOwners(settings.db_path)
        self.scans: dict[str, dict[str, Any]] = {}
        self.conversations = ConversationRegistry()
        self.executor = ThreadPoolExecutor(max_workers=SCAN_WORKERS)


def get_state(request: Request) -> AppState:
    state: AppState = request.app.state.haris
    return state
