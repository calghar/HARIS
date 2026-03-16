"""LLM-related API endpoints extracted from the main app.

Provides structured actions (summarize, explain, remediation, etc.)
as dedicated endpoints alongside the existing freeform Q&A.
"""

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan/{scan_id}", tags=["llm"])


def _get_session(scan_id: str):
    """Retrieve a completed session. Raises HTTPException on failure."""
    # Deferred import to avoid circular dependency
    from .app import ScanStatus, _get_scan_and_session

    scan, session = _get_scan_and_session(scan_id)
    if scan["status"] != ScanStatus.COMPLETED or not session:
        raise HTTPException(
            status_code=404,
            detail="Scan not found or not complete",
        )
    return session


def _get_qa(backend_name: str | None = None):
    """Create a ReportQA instance with the given backend."""
    from ..llm.base import create_backend, get_default_backend_name
    from ..llm.qa import ReportQA

    if not backend_name:
        backend_name = get_default_backend_name()
    backend = create_backend(backend_name)
    return ReportQA(backend=backend)


async def _safe_json(request: Request) -> dict:
    """Parse JSON body, returning empty dict on missing/invalid content."""
    try:
        return await request.json()
    except Exception:
        return {}


@router.post("/summarize")
async def summarize_scan(
    scan_id: str, request: Request
) -> JSONResponse:
    """Generate an audience-specific summary."""
    session = _get_session(scan_id)
    body = await request.json()
    audience = body.get("audience", "executive")
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.summarize(session, audience=audience)
        return JSONResponse({
            "answer": response.text,
            "model": response.model,
            "tokens": response.token_count,
        })
    except Exception as exc:
        logger.exception("Summarize failed for %s", scan_id)
        return JSONResponse(
            {"error": str(exc)}, status_code=500
        )


@router.post("/explain/{finding_id}")
async def explain_finding(
    scan_id: str, finding_id: str, request: Request
) -> JSONResponse:
    """Explain a specific finding."""
    session = _get_session(scan_id)
    body = await _safe_json(request)
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.explain_finding(session, finding_id)
        return JSONResponse({
            "answer": response.text,
            "model": response.model,
            "tokens": response.token_count,
        })
    except Exception as exc:
        logger.exception("Explain failed for %s/%s", scan_id, finding_id)
        return JSONResponse(
            {"error": str(exc)}, status_code=500
        )


@router.post("/remediation-plan")
async def remediation_plan(
    scan_id: str, request: Request
) -> JSONResponse:
    """Generate a remediation plan in the specified format."""
    session = _get_session(scan_id)
    body = await request.json()
    fmt = body.get("format", "markdown")
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.remediation_plan(session, format=fmt)
        return JSONResponse({
            "answer": response.text,
            "model": response.model,
            "tokens": response.token_count,
        })
    except Exception as exc:
        logger.exception("Remediation plan failed for %s", scan_id)
        return JSONResponse(
            {"error": str(exc)}, status_code=500
        )


@router.post("/test-cases")
async def generate_test_cases(
    scan_id: str, request: Request
) -> JSONResponse:
    """Generate CI security test cases from findings."""
    session = _get_session(scan_id)
    body = await _safe_json(request)
    framework = body.get("framework", "generic")
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.generate_test_cases(
            session, framework=framework
        )
        return JSONResponse({
            "answer": response.text,
            "model": response.model,
            "tokens": response.token_count,
        })
    except Exception as exc:
        logger.exception("Test cases failed for %s", scan_id)
        return JSONResponse(
            {"error": str(exc)}, status_code=500
        )


@router.post("/mitigations")
async def suggest_mitigations(
    scan_id: str, request: Request
) -> JSONResponse:
    """Suggest code-level mitigations for findings."""
    session = _get_session(scan_id)
    body = await _safe_json(request)
    stack = body.get("stack", "generic web")
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.suggest_mitigations(session, stack=stack)
        return JSONResponse({
            "answer": response.text,
            "model": response.model,
            "tokens": response.token_count,
        })
    except Exception as exc:
        logger.exception("Mitigations failed for %s", scan_id)
        return JSONResponse(
            {"error": str(exc)}, status_code=500
        )


@router.post("/filter-findings")
async def filter_findings(
    scan_id: str, request: Request
) -> JSONResponse:
    """Filter and explain findings matching a query."""
    session = _get_session(scan_id)
    body = await request.json()
    criteria = body.get("criteria", "").strip()
    if not criteria:
        raise HTTPException(
            status_code=400, detail="criteria is required"
        )
    backend_name = body.get("backend")

    try:
        qa = _get_qa(backend_name)
        response = qa.filter_findings(session, criteria)
        return JSONResponse({
            "answer": response.text,
            "model": response.model,
            "tokens": response.token_count,
        })
    except Exception as exc:
        logger.exception("Filter findings failed for %s", scan_id)
        return JSONResponse(
            {"error": str(exc)}, status_code=500
        )
