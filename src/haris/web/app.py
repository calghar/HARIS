import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import cache

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

# Trigger @register_scanner / @register_check decorators
from .. import __version__, checks, scanners  # noqa: F401
from ..auth.bootstrap import bootstrap_admin_from_env
from ..auth.csrf import csrf_protect
from ..auth.redirects import login_url
from ..auth.security_headers import SecurityHeadersMiddleware
from . import scan_runtime
from .logging_setup import configure_logging
from .routers import ALL_ROUTERS
from .routing import API_PREFIX
from .settings import WebSettings
from .state import AppState
from .templating import STATIC_DIR

logger = logging.getLogger(__name__)

SESSION_CLEANUP_INTERVAL_S = 3600


async def _periodic_session_cleanup(state: AppState) -> None:
    """Purge expired sessions every hour in the background."""
    while True:
        await asyncio.sleep(SESSION_CLEANUP_INTERVAL_S)
        try:
            count = state.auth.purge_expired_sessions()
            if count:
                logger.debug("Purged %d expired sessions/tokens", count)
        except Exception as exc:
            logger.warning("Session cleanup error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    state: AppState = app.state.haris
    bootstrap_admin_from_env(state.auth)
    cleanup_task = asyncio.create_task(_periodic_session_cleanup(state))
    state.jobs.dispatch()
    yield
    cleanup_task.cancel()
    state.jobs.shutdown()


def create_app(settings: WebSettings | None = None) -> FastAPI:
    settings = settings or WebSettings.from_env()
    configure_logging(settings.log_dir)
    app = FastAPI(
        title="HARIS",
        description="Black-box web security audit dashboard",
        version=__version__,
        lifespan=lifespan,
        dependencies=[Depends(csrf_protect)],
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.haris = AppState(settings, scan_runtime.execute_scan)

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> Response:
        """Unauthenticated HTML requests go to /login; API/HTMX callers get JSON."""
        htmx = request.headers.get("HX-Request") == "true"
        is_api = request.url.path.startswith(API_PREFIX + "/")
        if exc.status_code == 401 and not htmx and not is_api:
            return RedirectResponse(login_url(request), status_code=303)
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=dict(exc.headers or {}),
        )

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        same_site="lax",
        https_only=settings.force_https,
    )
    app.add_middleware(SecurityHeadersMiddleware, force_https=settings.force_https)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    for router in ALL_ROUTERS:
        app.include_router(router)
    return app


@cache
def _default_app() -> FastAPI:
    return create_app()


def __getattr__(name: str) -> FastAPI:
    """`haris.web.app:app` builds the app on first access, not on import."""
    if name == "app":
        return _default_app()
    raise AttributeError(name)
