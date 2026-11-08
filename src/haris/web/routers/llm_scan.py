import logging
from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ...auth.middleware import require_user
from ...auth.models import User
from ...llm.base import create_backend, get_default_backend_name
from ...llm.qa import ReportQA
from ..routing import protected_router
from ..scan_runtime import get_completed_session
from ..state import AppState, get_state

logger = logging.getLogger(__name__)

router = protected_router(prefix="/api/scan/{scan_id}", tags=["llm"])


def _get_qa(backend_name: str | None = None) -> ReportQA:
    """Create a ReportQA instance with the given backend."""
    if not backend_name:
        backend_name = get_default_backend_name()
    backend = create_backend(backend_name)
    return ReportQA(backend=backend)


async def _safe_json(request: Request) -> dict[str, Any]:
    """Parse JSON body, returning empty dict on missing/invalid content."""
    try:
        body: dict[str, Any] = await request.json()
        return body
    except Exception:
        return {}


@router.post("/summarize")
async def summarize_scan(
    scan_id: str,
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    """Generate an audience-specific summary."""
    session = get_completed_session(state, user, scan_id)
    body = await request.json()
    audience = body.get("audience", "executive")
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.summarize(session, audience=audience)
        return JSONResponse(
            {
                "answer": response.text,
                "model": response.model,
                "tokens": response.token_count,
            }
        )
    except Exception as exc:
        logger.exception("Summarize failed for %s", scan_id)
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.post("/explain/{finding_id}")
async def explain_finding(
    scan_id: str,
    finding_id: str,
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    """Explain a specific finding."""
    session = get_completed_session(state, user, scan_id)
    body = await _safe_json(request)
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.explain_finding(session, finding_id)
        return JSONResponse(
            {
                "answer": response.text,
                "model": response.model,
                "tokens": response.token_count,
            }
        )
    except Exception as exc:
        logger.exception("Explain failed for %s/%s", scan_id, finding_id)
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.post("/remediation-plan")
async def remediation_plan(
    scan_id: str,
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    """Generate a remediation plan in the specified format."""
    session = get_completed_session(state, user, scan_id)
    body = await request.json()
    fmt = body.get("format", "markdown")
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.remediation_plan(session, format=fmt)
        return JSONResponse(
            {
                "answer": response.text,
                "model": response.model,
                "tokens": response.token_count,
            }
        )
    except Exception as exc:
        logger.exception("Remediation plan failed for %s", scan_id)
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.post("/test-cases")
async def generate_test_cases(
    scan_id: str,
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    """Generate CI security test cases from findings."""
    session = get_completed_session(state, user, scan_id)
    body = await _safe_json(request)
    framework = body.get("framework", "generic")
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.generate_test_cases(session, framework=framework)
        return JSONResponse(
            {
                "answer": response.text,
                "model": response.model,
                "tokens": response.token_count,
            }
        )
    except Exception as exc:
        logger.exception("Test cases failed for %s", scan_id)
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.post("/mitigations")
async def suggest_mitigations(
    scan_id: str,
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    """Suggest code-level mitigations for findings."""
    session = get_completed_session(state, user, scan_id)
    body = await _safe_json(request)
    stack = body.get("stack", "generic web")
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.suggest_mitigations(session, stack=stack)
        return JSONResponse(
            {
                "answer": response.text,
                "model": response.model,
                "tokens": response.token_count,
            }
        )
    except Exception as exc:
        logger.exception("Mitigations failed for %s", scan_id)
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.post("/filter-findings")
async def filter_findings(
    scan_id: str,
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    """Filter and explain findings matching a query."""
    session = get_completed_session(state, user, scan_id)
    body = await request.json()
    criteria = body.get("criteria", "").strip()
    if not criteria:
        raise HTTPException(status_code=400, detail="criteria is required")
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.filter_findings(session, criteria)
        return JSONResponse(
            {
                "answer": response.text,
                "model": response.model,
                "tokens": response.token_count,
            }
        )
    except Exception as exc:
        logger.exception("Filter findings failed for %s", scan_id)
        return JSONResponse({"error": str(exc)}, status_code=500)
