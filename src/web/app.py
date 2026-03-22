import asyncio
import logging
import logging.handlers
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Trigger @register_scanner / @register_check decorators
import src.checks  # noqa: F401
import src.scanners  # noqa: F401

from ..core.decorators import all_registered
from ..core.profiles import PROFILES
from ..core.risk import get_business_impact
from ..core.runner import ScanRunner
from ..db.store import ScanStore
from ..models import AuthConfig, ScanConfigTemplate, ScanSession, Scope, Target
from ..models.chat import Conversation
from ..reporting import REPORTER_REGISTRY
from .llm_routes import router as llm_router

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
REPORTS_DIR = Path("./reports")
ASSETS_DIR = Path(__file__).resolve().parents[2] / "assets"
LOG_DIR = Path("./data/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

_log_fmt = logging.Formatter(
    "%(asctime)s %(levelname)-5s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_file_handler = logging.handlers.RotatingFileHandler(
    LOG_DIR / "haris.log",
    maxBytes=5 * 1024 * 1024,
    backupCount=3,
)
_file_handler.setFormatter(_log_fmt)
_file_handler.setLevel(logging.DEBUG)

_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(_log_fmt)
_stream_handler.setLevel(logging.INFO)

logging.basicConfig(
    level=logging.INFO,
    handlers=[_file_handler, _stream_handler],
)

app = FastAPI(
    title="HARIS",
    description="Black-box web security audit dashboard",
    version="0.4.0",
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")
app.include_router(llm_router)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

_executor = ThreadPoolExecutor(max_workers=2)
_store = ScanStore()
_scans: dict[str, dict[str, Any]] = {}
_conversations: dict[str, Conversation] = {}
_CONVERSATION_MAX_AGE_S = 7200  # 2 hours
_CONVERSATION_MAX_COUNT = 50


def _domain_slug(url: str) -> str:
    """Extract a filesystem-safe domain slug from a URL."""
    hostname = urlparse(url).hostname or "unknown"
    return re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)


class ScanStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

_SCANNER_INFO = [
    {
        "name": "Nuclei",
        "description": "Template-based CVE, misconfiguration, and exposure scanner",
        "version": "3.x",
        "icon": "radar",
    },
    {
        "name": "Nikto",
        "description": "Web server misconfiguration and outdated software scanner",
        "version": "2.x",
        "icon": "search",
    },
    {
        "name": "Wapiti",
        "description": "Black-box web application vulnerability scanner",
        "version": "3.x",
        "icon": "shield",
    },
    {
        "name": "Nmap",
        "description": "Network reconnaissance and port/service scanner",
        "version": "7.x",
        "icon": "network",
    },
    {
        "name": "SSLyze",
        "description": "TLS/SSL configuration and certificate analyser",
        "version": "6.x",
        "icon": "lock",
    },
]


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    summary = _store.dashboard_summary()
    # Merge in-memory running scans count
    running = sum(1 for s in _scans.values() if s["status"] == ScanStatus.RUNNING)
    if running:
        summary["total_scans"] += running
    hostnames = sorted({w["hostname"] for w in _store.list_websites()})
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "nav_active": "dashboard",
            "summary": summary,
            "scanners": _SCANNER_INFO,
            "hostnames": hostnames,
        },
    )


@app.get("/websites", response_class=HTMLResponse)
async def websites_page(request: Request) -> HTMLResponse:
    websites = _store.list_websites()
    return templates.TemplateResponse(
        "websites.html",
        {
            "request": request,
            "nav_active": "websites",
            "websites": websites,
        },
    )


@app.get("/website/{hostname}", response_class=HTMLResponse)
async def website_detail(request: Request, hostname: str) -> HTMLResponse:
    scans = _store.get_scans_for_hostname(hostname)
    first_scanned = scans[-1]["started_at"] if scans else ""
    last_scanned = scans[0]["started_at"] if scans else ""
    # Build template name lookup
    all_templates = _store.list_scan_config_templates()
    template_names = {t["template_id"]: t["name"] for t in all_templates}
    return templates.TemplateResponse(
        "website_detail.html",
        {
            "request": request,
            "nav_active": "websites",
            "hostname": hostname,
            "scans": scans,
            "first_scanned": first_scanned,
            "last_scanned": last_scanned,
            "template_names": template_names,
        },
    )


@app.get("/scans", response_class=HTMLResponse)
async def scans_page(
    request: Request,
    page: int = 1,
    hostname: str = "",
    severity: str = "",
    date_from: str = "",
    date_to: str = "",
) -> HTMLResponse:
    per_page = 5
    rows, total = _store.list_sessions_paginated(
        page=page,
        per_page=per_page,
        hostname=hostname or None,
        severity=severity or None,
        date_from=date_from or None,
        date_to=date_to or None,
    )
    # Merge in-memory running scans for first page with no filters
    scans = rows
    if page == 1 and not any([hostname, severity, date_from, date_to]):
        memory_scans = [
            {
                "session_id": s["scan_id"],
                "scan_id": s["scan_id"],
                "target_url": s["target_url"],
                "profile_name": s.get("profile", ""),
                "status": s["status"],
                "started_at": s.get("started_at", ""),
                "risk_posture": "",
                "finding_count": (
                    len(s["session"].all_findings) if s.get("session") else 0
                ),
            }
            for s in _scans.values()
            if s["status"] in (ScanStatus.RUNNING, ScanStatus.PENDING)
        ]
        scans = memory_scans + scans
        total += len(memory_scans)

    total_pages = max(1, (total + per_page - 1) // per_page)
    hostnames = sorted({w["hostname"] for w in _store.list_websites()})

    pagination = {
        "page": page,
        "total_pages": total_pages,
        "per_page": per_page,
        "hostname": hostname,
        "severity": severity,
        "date_from": date_from,
        "date_to": date_to,
    }

    return templates.TemplateResponse(
        "scans.html",
        {
            "request": request,
            "nav_active": "scans",
            "scans": scans,
            "total": total,
            "hostnames": hostnames,
            "filters": {
                "hostname": hostname,
                "severity": severity,
                "date_from": date_from,
                "date_to": date_to,
            },
            "pagination": pagination,
        },
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    summary = _store.dashboard_summary()
    all_scanners = sorted(all_registered().keys())
    llm_config: dict[str, Any] = {}
    template_dir = "./templates"
    try:
        from ..config.loader import load_config as _load_cfg

        cfg = _load_cfg()
        llm_config = {
            "backend": cfg.llm.backend,
            "enrichment_enabled": cfg.llm.enrichment_enabled,
            "threshold": cfg.llm.enrich_severity_threshold,
        }
        template_dir = cfg.template_dir
    except Exception:
        pass

    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "nav_active": "settings",
            "scanners": all_scanners,
            "llm_backend": llm_config.get("backend", "anthropic"),
            "llm_enrichment_enabled": llm_config.get("enrichment_enabled", False),
            "enrich_threshold": llm_config.get("threshold", "high"),
            "total_scans": summary.get("total_scans", 0),
            "total_websites": summary.get("total_websites", 0),
            "template_dir": template_dir,
        },
    )


@app.get("/licenses", response_class=HTMLResponse)
async def licenses_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "licenses.html",
        {
            "request": request,
            "nav_active": "",
            "scanners": _SCANNER_INFO,
        },
    )


@app.get("/scan/new", response_class=HTMLResponse)
async def new_scan_form(
    request: Request,
    rescan: str | None = Query(default=None),
) -> HTMLResponse:
    all_scanners = all_registered()
    scan_templates = _store.list_scan_config_templates()
    prefill: dict[str, Any] = {}
    if rescan:
        try:
            _, session = _get_scan_and_session(rescan)
            if session:
                prefill = {
                    "target_url": session.target.base_url,
                    "profile": session.profile_name,
                    "rate_limit": session.target.scope.rate_limit_rps,
                    "max_requests": session.target.scope.max_requests,
                    "excluded_paths": "\n".join(
                        session.target.scope.excluded_paths or []
                    ),
                    "auth_method": session.target.auth.method,
                    "auth_header_value": session.target.auth.header_value or "",
                }
        except HTTPException:
            pass
    return templates.TemplateResponse(
        "scan_new.html",
        {
            "request": request,
            "nav_active": "new",
            "profiles": list(PROFILES.values()),
            "available_scanners": sorted(all_scanners.keys()),
            "scan_templates": scan_templates,
            "prefill": prefill,
        },
    )


def _get_scan_and_session(
    scan_id: str,
) -> tuple[dict[str, Any], ScanSession | None]:
    scan = _scans.get(scan_id)
    if scan:
        return scan, scan.get("session")

    session = _store.load_session(scan_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = {
        "scan_id": scan_id,
        "target_url": session.target.base_url,
        "profile": session.profile_name,
        "status": ScanStatus.COMPLETED,
        "started_at": session.started_at,
        "finished_at": session.finished_at,
        "session": session,
        "report_formats": ["markdown", "json", "html"],
        "error": None,
    }
    _scans[scan_id] = scan
    return scan, session


@app.get(
    "/scan/{scan_id}",
    response_class=HTMLResponse,
    responses={404: {"description": "Scan not found"}},
)
async def scan_detail(request: Request, scan_id: str) -> HTMLResponse:
    scan, session = _get_scan_and_session(scan_id)

    business_impacts = {}
    if session:
        for f in session.all_findings:
            business_impacts[f.finding_id] = get_business_impact(f)

    return templates.TemplateResponse(
        "scan_detail.html",
        {
            "request": request,
            "nav_active": "scans",
            "scan": scan,
            "session": session,
            "business_impacts": business_impacts,
        },
    )


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.post(
    "/api/scan/start",
    responses={400: {"description": "Bad request"}},
)
async def start_scan(request: Request) -> JSONResponse:
    form = await request.form()

    target_url = str(form.get("target_url", "")).strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="target_url is required")

    profile_name = str(form.get("profile", "quick"))
    report_formats: list[str] = [str(f) for f in form.getlist("report_formats")] or [
        "markdown",
        "json",
    ]

    excluded_paths_raw = str(form.get("excluded_paths", "")).strip()
    excluded_paths = [p.strip() for p in excluded_paths_raw.split("\n") if p.strip()]

    rate_limit = float(str(form.get("rate_limit", 10.0)))
    max_requests = int(str(form.get("max_requests", 10000)))

    auth_method = str(form.get("auth_method", "none"))
    auth_header_value = str(form.get("auth_header_value", ""))

    llm_enrich = bool(form.get("llm_enrich"))
    llm_backend_name = str(form.get("llm_backend", "")).strip() or None
    template_id = str(form.get("template_id", "")).strip()

    # If a template is selected, merge its settings (form overrides template)
    scanner_options: dict[str, dict[str, Any]] = {}
    if template_id:
        tpl = _store.get_scan_config_template(template_id)
        if tpl:
            scanner_options = dict(tpl.scanner_options)
            if not profile_name or profile_name == "quick":
                profile_name = tpl.profile
            if not form.get("rate_limit"):
                rate_limit = tpl.rate_limit_rps
            if not form.get("max_requests"):
                max_requests = tpl.max_requests
            if not excluded_paths:
                excluded_paths = list(tpl.excluded_paths)
            if not llm_enrich and tpl.llm_enrichment:
                llm_enrich = True
                if not llm_backend_name and tpl.llm_backend:
                    llm_backend_name = tpl.llm_backend

    scan_id = uuid.uuid4().hex[:10]
    now = datetime.now(UTC).isoformat()

    _scans[scan_id] = {
        "scan_id": scan_id,
        "target_url": target_url,
        "profile": profile_name,
        "status": ScanStatus.PENDING,
        "started_at": now,
        "finished_at": None,
        "session": None,
        "report_formats": list(report_formats),
        "llm_enrich": llm_enrich,
        "template_id": template_id,
        "error": None,
    }

    scope = Scope(
        excluded_paths=excluded_paths,
        rate_limit_rps=rate_limit,
        max_requests=max_requests,
    )
    auth = AuthConfig(method=auth_method, header_value=auth_header_value)
    target = Target(base_url=target_url, scope=scope, auth=auth)

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        _executor,
        _run_scan_blocking,
        scan_id,
        target,
        profile_name,
        list(report_formats),
        llm_enrich,
        llm_backend_name,
        template_id,
        scanner_options,
    )

    return JSONResponse(
        {"scan_id": scan_id, "status": "pending", "redirect": f"/scan/{scan_id}"},
        status_code=202,
    )


@app.get(
    "/api/scan/{scan_id}/status",
    responses={404: {"description": "Scan not found"}},
)
async def scan_status(scan_id: str) -> JSONResponse:
    scan, session = _get_scan_and_session(scan_id)
    return JSONResponse(
        {
            "scan_id": scan_id,
            "status": scan["status"],
            "finished_at": scan.get("finished_at"),
            "total_findings": len(session.all_findings) if session else 0,
            "risk_posture": session.risk_posture.value if session else None,
            "llm_enrichment_enabled": scan.get("llm_enrich", False),
            "error": scan.get("error"),
        }
    )


@app.get(
    "/api/scan/{scan_id}/report/{fmt}",
    responses={
        404: {"description": "Scan not found or not complete"},
        400: {"description": "Unknown format"},
    },
)
async def download_report(scan_id: str, fmt: str) -> FileResponse:
    scan, session = _get_scan_and_session(scan_id)
    if scan["status"] != ScanStatus.COMPLETED or not session:
        raise HTTPException(status_code=404, detail="Scan not found or not complete")

    reporter_cls = REPORTER_REGISTRY.get(fmt)
    if not reporter_cls:
        raise HTTPException(status_code=400, detail=f"Unknown format: {fmt}")

    reporter = reporter_cls()
    domain = _domain_slug(session.target.base_url)
    filename = f"report_{domain}_{scan_id}{reporter.file_extension}"
    out_path = REPORTS_DIR / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    reporter.write(session, out_path)

    return FileResponse(
        path=str(out_path),
        filename=filename,
        media_type="application/octet-stream",
    )


# ---------------------------------------------------------------------------
# Scan history API
# ---------------------------------------------------------------------------


@app.get("/api/scans", response_model=None)
async def list_scans(
    request: Request,
    page: int = 1,
    per_page: int = 5,
    hostname: str = "",
    severity: str = "",
    date_from: str = "",
    date_to: str = "",
    format: str = "",
) -> JSONResponse | HTMLResponse:
    rows, total = _store.list_sessions_paginated(
        page=page,
        per_page=per_page,
        hostname=hostname or None,
        severity=severity or None,
        date_from=date_from or None,
        date_to=date_to or None,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)

    if format == "html":
        pagination = {
            "page": page,
            "total_pages": total_pages,
            "per_page": per_page,
            "hostname": hostname,
            "severity": severity,
            "date_from": date_from,
            "date_to": date_to,
        }
        html = templates.get_template("_scan_rows.html").render(
            scans=rows,
            pagination=pagination,
        )
        return HTMLResponse(html)

    return JSONResponse(
        {
            "scans": rows,
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
        }
    )


@app.get("/api/dashboard/summary")
async def api_dashboard_summary() -> JSONResponse:
    return JSONResponse(_store.dashboard_summary())


@app.get("/api/websites")
async def api_list_websites() -> JSONResponse:
    return JSONResponse(_store.list_websites())


@app.get("/api/website/{hostname}/scans")
async def api_website_scans(hostname: str) -> JSONResponse:
    return JSONResponse(_store.get_scans_for_hostname(hostname))


@app.get("/api/website/{hostname}/trends")
async def api_website_trends(hostname: str) -> JSONResponse:
    return JSONResponse(_store.get_severity_trends(hostname))


@app.delete(
    "/api/scan/{scan_id}",
    responses={
        404: {"description": "Scan not found"},
        409: {"description": "Scan is still running"},
    },
)
async def delete_scan(scan_id: str) -> JSONResponse:
    scan = _scans.get(scan_id)
    if scan and scan["status"] == ScanStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Cannot delete a running scan")

    deleted = False

    # Remove from in-memory store
    if _scans.pop(scan_id, None) is not None:
        deleted = True

    # Remove from database (cascades to findings + remediation_steps)
    if _store.delete_session(scan_id):
        deleted = True

    # Remove report files from disk
    for report_file in REPORTS_DIR.glob(f"*_{scan_id}.*"):
        report_file.unlink(missing_ok=True)

    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")

    return JSONResponse({"deleted": scan_id}, status_code=200)


@app.get(
    "/api/scan/{scan_id}/findings",
    responses={404: {"description": "Scan not found"}},
)
async def get_scan_findings(
    scan_id: str,
    severity: str | None = None,
    owasp: str | None = None,
) -> JSONResponse:
    scan = _scans.get(scan_id)
    if scan and scan.get("session"):
        session = scan["session"]
        findings = session.all_findings
        if severity:
            findings = [f for f in findings if f.severity.value == severity]
        if owasp:
            findings = [f for f in findings if owasp in (f.owasp_category or "")]
        return JSONResponse(
            [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "owasp_category": f.owasp_category,
                    "url": f.url,
                    "scanner": f.scanner,
                    "remediation": f.remediation,
                }
                for f in findings
            ]
        )

    try:
        rows = _store.get_findings(scan_id, severity=severity, owasp_category=owasp)
        return JSONResponse(rows)
    except Exception as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc


# ---------------------------------------------------------------------------
# LLM endpoints
# ---------------------------------------------------------------------------


@app.get("/api/llm/backends")
async def llm_backends() -> JSONResponse:
    """Return available LLM backends and which is the current default."""
    from ..llm.base import get_available_backends, get_default_backend_name

    backends = get_available_backends()
    return JSONResponse(
        {
            "backends": backends,
            "default": get_default_backend_name(),
        }
    )


@app.get(
    "/api/scan/{scan_id}/enrichment",
    responses={404: {"description": "Scan not found or not complete"}},
)
async def get_enrichment(scan_id: str) -> JSONResponse:
    """Return LLM enrichment data for a completed scan."""
    scan, session = _get_scan_and_session(scan_id)
    if scan["status"] != ScanStatus.COMPLETED or not session:
        raise HTTPException(status_code=404, detail="Scan not found or not complete")

    enrichments = {fid: e.model_dump() for fid, e in session.llm_enrichments.items()}
    chains = [c.model_dump() for c in session.attack_chains]
    triaged = [t.model_dump() for t in session.triaged_findings]

    return JSONResponse(
        {
            "enrichments": enrichments,
            "attack_chains": chains,
            "triaged_findings": triaged,
            "has_enrichment": bool(enrichments or chains or triaged),
        }
    )


@app.post(
    "/api/scan/{scan_id}/ask",
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Scan not found or not complete"},
    },
)
async def ask_about_scan(scan_id: str, request: Request) -> JSONResponse:
    scan, session = _get_scan_and_session(scan_id)
    if scan["status"] != ScanStatus.COMPLETED or not session:
        raise HTTPException(status_code=404, detail="Scan not found or not complete")

    body = await request.json()
    question = body.get("question", "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="question is required")

    backend_name = body.get("backend")

    try:
        from ..llm.base import create_backend, get_default_backend_name
        from ..llm.qa import ReportQA

        if not backend_name:
            backend_name = get_default_backend_name()

        backend = create_backend(backend_name)
        qa = ReportQA(backend=backend)
        response = qa.ask(session, question)

        return JSONResponse(
            {
                "answer": response.text,
                "model": response.model,
                "tokens": response.token_count,
            }
        )

    except ImportError as exc:
        return JSONResponse(
            {"error": f"LLM backend not available: {exc}"},
            status_code=501,
        )
    except Exception as exc:
        logger.exception("LLM query failed for scan %s", scan_id)
        return JSONResponse({"error": str(exc)}, status_code=500)


def _evict_expired_conversations() -> None:
    """Remove expired conversations, keeping under the max count."""
    now = datetime.now(UTC)
    expired = [
        cid
        for cid, conv in _conversations.items()
        if (now - datetime.fromisoformat(conv.created_at)).total_seconds()
        > _CONVERSATION_MAX_AGE_S
    ]
    for cid in expired:
        del _conversations[cid]
    # If still over limit, drop oldest
    while len(_conversations) > _CONVERSATION_MAX_COUNT:
        oldest = min(_conversations, key=lambda k: _conversations[k].created_at)
        del _conversations[oldest]


@app.post(
    "/api/scan/{scan_id}/chat",
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Scan not found or not complete"},
    },
)
async def chat_with_scan(scan_id: str, request: Request) -> JSONResponse:
    """Multi-turn chat about a completed scan."""
    scan, session = _get_scan_and_session(scan_id)
    if scan["status"] != ScanStatus.COMPLETED or not session:
        raise HTTPException(
            status_code=404,
            detail="Scan not found or not complete",
        )

    body = await request.json()
    question = body.get("question", "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="question is required")

    conv_id = body.get("conversation_id")
    backend_name = body.get("backend")

    _evict_expired_conversations()

    try:
        from ..llm.base import create_backend, get_default_backend_name
        from ..llm.qa import ReportQA

        if not backend_name:
            backend_name = get_default_backend_name()

        # Get or create conversation
        conv: Conversation | None = None
        if conv_id:
            conv = _conversations.get(conv_id)

        if conv is None:
            conv_id = uuid.uuid4().hex[:12]
            conv = Conversation(
                conversation_id=conv_id,
                scan_id=scan_id,
                backend_name=backend_name,
            )
            _conversations[conv_id] = conv

        backend = create_backend(backend_name)
        qa = ReportQA(backend=backend)

        # Enrich question with template context if available
        if session.template_id:
            tpl = _store.get_scan_config_template(session.template_id)
            if tpl:
                question = (
                    f"[Context: This scan used configuration template "
                    f"'{tpl.name}': {tpl.description}. "
                    f"Profile: {tpl.profile}.]\n\n{question}"
                )

        response = qa.chat(session, question, conv.messages)

        # Record both messages
        conv.add_message("user", question)
        conv.add_message(
            "assistant",
            response.text,
            token_count=response.token_count,
        )

        return JSONResponse(
            {
                "answer": response.text,
                "model": response.model,
                "tokens": response.token_count,
                "conversation_id": conv_id,
                "message_count": conv.message_count,
                "total_tokens": conv.total_tokens,
            }
        )

    except ImportError as exc:
        return JSONResponse(
            {"error": f"LLM backend not available: {exc}"},
            status_code=501,
        )
    except Exception as exc:
        logger.exception("Chat failed for scan %s", scan_id)
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.get(
    "/api/scan/{scan_id}/chat/{conversation_id}",
    responses={404: {"description": "Conversation not found"}},
)
async def get_conversation(scan_id: str, conversation_id: str) -> JSONResponse:
    """Retrieve conversation history."""
    conv = _conversations.get(conversation_id)
    if conv is None or conv.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return JSONResponse(
        {
            "conversation_id": conv.conversation_id,
            "messages": [m.model_dump() for m in conv.messages],
            "total_tokens": conv.total_tokens,
        }
    )


@app.delete(
    "/api/scan/{scan_id}/chat/{conversation_id}",
    responses={404: {"description": "Conversation not found"}},
)
async def delete_conversation(scan_id: str, conversation_id: str) -> JSONResponse:
    """Clear a conversation."""
    conv = _conversations.get(conversation_id)
    if conv is None or conv.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="Conversation not found")
    del _conversations[conversation_id]
    return JSONResponse({"deleted": conversation_id})


# ---------------------------------------------------------------------------
# Template management endpoints
# ---------------------------------------------------------------------------


@app.get("/api/templates/status")
async def template_status() -> JSONResponse:
    try:
        from ..config.loader import load_config
        from ..templates.manager import TemplateManager

        config = load_config()
        mgr = TemplateManager(
            base_dir=config.template_dir,
            sources=config.template_sources,
        )
        metadata = mgr.list_sources()
        return JSONResponse([m.model_dump() for m in metadata])
    except Exception as exc:
        logger.warning("Could not load template status: %s", exc)
        return JSONResponse([], status_code=200)


@app.post("/api/templates/update")
async def trigger_template_update(request: Request) -> JSONResponse:
    body = await request.json() if request.headers.get("content-type") else {}
    scanner_name = body.get("scanner")
    source_name = body.get("source_name")
    force = body.get("force", False)

    try:
        from ..config.loader import load_config
        from ..templates.manager import TemplateManager

        config = load_config()
        # Filter sources when a specific source_name is requested
        sources = config.template_sources
        if source_name:
            sources = [s for s in sources if s.name == source_name]
        mgr = TemplateManager(
            base_dir=config.template_dir,
            sources=sources,
        )

        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            _executor,
            lambda: mgr.update_templates(scanner_name=scanner_name, force=force),
        )

        return JSONResponse(
            [r.model_dump() for r in results],
            status_code=200,
        )
    except Exception as exc:
        logger.exception("Template update failed")
        return JSONResponse({"error": str(exc)}, status_code=500)


# ---------------------------------------------------------------------------
# Scan configuration templates
# ---------------------------------------------------------------------------


@app.get("/templates", response_class=HTMLResponse)
async def templates_page(request: Request) -> HTMLResponse:
    scan_templates = _store.list_scan_config_templates()
    # Scanner template sources
    scanner_sources: list[dict[str, Any]] = []
    try:
        from ..config.loader import load_config as _load_cfg
        from ..templates.manager import TemplateManager

        cfg = _load_cfg()
        mgr = TemplateManager(
            base_dir=cfg.template_dir,
            sources=cfg.template_sources,
        )
        # Index downloaded metadata by source_name
        meta_by_name = {m.source_name: m.model_dump() for m in mgr.list_sources()}
        # Show ALL configured sources (downloaded or not)
        for src in cfg.template_sources:
            if src.name in meta_by_name:
                scanner_sources.append(meta_by_name[src.name])
            else:
                scanner_sources.append(
                    {
                        "source_name": src.name,
                        "scanner": src.scanner,
                        "template_count": None,
                        "last_updated": None,
                        "local_path": None,
                    }
                )
    except Exception:
        pass

    return templates.TemplateResponse(
        "templates.html",
        {
            "request": request,
            "nav_active": "templates",
            "scan_templates": scan_templates,
            "scanner_sources": scanner_sources,
        },
    )


@app.get("/templates/new", response_class=HTMLResponse)
async def template_new_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "template_form.html",
        {
            "request": request,
            "nav_active": "templates",
            "profiles": list(PROFILES.values()),
            "template": None,
        },
    )


@app.get("/templates/{template_id}/edit", response_class=HTMLResponse)
async def template_edit_form(
    request: Request,
    template_id: str,
) -> HTMLResponse:
    tpl = _store.get_scan_config_template(template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="Template not found")
    return templates.TemplateResponse(
        "template_form.html",
        {
            "request": request,
            "nav_active": "templates",
            "profiles": list(PROFILES.values()),
            "template": tpl.model_dump(),
        },
    )


@app.get("/api/scan-templates")
async def api_list_scan_templates() -> JSONResponse:
    return JSONResponse(_store.list_scan_config_templates())


@app.get("/api/scan-templates/{template_id}")
async def api_get_scan_template(template_id: str) -> JSONResponse:
    tpl = _store.get_scan_config_template(template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="Template not found")
    return JSONResponse(tpl.model_dump())


@app.post("/api/scan-templates")
async def api_create_scan_template(request: Request) -> JSONResponse:
    body = await request.json()
    now = datetime.now(UTC).isoformat()
    tpl = ScanConfigTemplate(
        name=body["name"],
        description=body.get("description", ""),
        profile=body.get("profile", "quick"),
        rate_limit_rps=float(body.get("rate_limit_rps", 10.0)),
        max_requests=int(body.get("max_requests", 10000)),
        excluded_paths=body.get("excluded_paths", []),
        auth_method=body.get("auth_method", "none"),
        report_formats=body.get("report_formats", ["markdown", "json"]),
        llm_enrichment=bool(body.get("llm_enrichment", False)),
        llm_backend=body.get("llm_backend", ""),
        scanner_options=body.get("scanner_options", {}),
        tags=body.get("tags", []),
        created_at=now,
        updated_at=now,
    )
    _store.save_scan_config_template(tpl)
    return JSONResponse(tpl.model_dump(), status_code=201)


@app.put("/api/scan-templates/{template_id}")
async def api_update_scan_template(
    template_id: str,
    request: Request,
) -> JSONResponse:
    existing = _store.get_scan_config_template(template_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Template not found")
    body = await request.json()
    now = datetime.now(UTC).isoformat()
    updated = ScanConfigTemplate(
        template_id=template_id,
        name=body.get("name", existing.name),
        description=body.get("description", existing.description),
        profile=body.get("profile", existing.profile),
        rate_limit_rps=float(
            body.get("rate_limit_rps", existing.rate_limit_rps),
        ),
        max_requests=int(
            body.get("max_requests", existing.max_requests),
        ),
        excluded_paths=body.get("excluded_paths", existing.excluded_paths),
        auth_method=body.get("auth_method", existing.auth_method),
        report_formats=body.get(
            "report_formats",
            existing.report_formats,
        ),
        llm_enrichment=bool(
            body.get("llm_enrichment", existing.llm_enrichment),
        ),
        llm_backend=body.get("llm_backend", existing.llm_backend),
        scanner_options=body.get(
            "scanner_options",
            existing.scanner_options,
        ),
        tags=body.get("tags", existing.tags),
        is_default=existing.is_default,
        created_at=existing.created_at,
        updated_at=now,
    )
    _store.save_scan_config_template(updated)
    return JSONResponse(updated.model_dump())


@app.delete("/api/scan-templates/{template_id}")
async def api_delete_scan_template(template_id: str) -> JSONResponse:
    if not _store.delete_scan_config_template(template_id):
        raise HTTPException(status_code=404, detail="Template not found")
    return JSONResponse({"deleted": template_id})


@app.post("/api/scan-templates/{template_id}/set-default")
async def api_set_default_template(template_id: str) -> JSONResponse:
    tpl = _store.get_scan_config_template(template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="Template not found")
    _store.set_default_scan_config_template(template_id)
    return JSONResponse({"default": template_id})


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------


def _run_scan_blocking(
    scan_id: str,
    target: Target,
    profile_name: str,
    report_formats: list[str],
    llm_enrich: bool = False,
    llm_backend_name: str | None = None,
    template_id: str = "",
    scanner_options: dict[str, dict[str, Any]] | None = None,
) -> None:
    scan = _scans[scan_id]
    scan["status"] = ScanStatus.RUNNING

    try:
        runner = ScanRunner(
            target=target,
            profile_name=profile_name,
            session_id=scan_id,
            llm_enrich=llm_enrich,
            llm_backend_name=llm_backend_name,
            scanner_options=scanner_options,
        )
        session = runner.run()
        session.template_id = template_id

        scan["session"] = session
        scan["status"] = ScanStatus.COMPLETED
        scan["finished_at"] = datetime.now(UTC).isoformat()

        try:
            _store.save_session(session)
            logger.info("Saved session %s to database", scan_id)
        except Exception as db_exc:
            logger.warning("Could not save session to database: %s", db_exc)

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        domain = _domain_slug(target.base_url)
        for fmt in report_formats:
            reporter_cls = REPORTER_REGISTRY.get(fmt)
            if reporter_cls:
                reporter = reporter_cls()
                filename = f"report_{domain}_{scan_id}{reporter.file_extension}"
                reporter.write(session, REPORTS_DIR / filename)

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        scan["status"] = ScanStatus.FAILED
        scan["error"] = str(exc)
        scan["finished_at"] = datetime.now(UTC).isoformat()
