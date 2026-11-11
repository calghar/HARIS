from fastapi import Depends

from ...auth.middleware import require_user
from ...auth.models import User
from ..llm_support import answer, llm_errors, make_qa
from ..routing import api_router
from ..scan_runtime import get_completed_session
from ..schemas.llm import (
    Answer,
    ExplainIn,
    FilterIn,
    MitigationsIn,
    RemediationIn,
    SummarizeIn,
    TestCasesIn,
)
from ..state import AppState, get_state

router = api_router("scans:read", "scans:write", prefix="/llm", tags=["llm"])


@router.post("/summarize")
async def summarize_scan(
    body: SummarizeIn,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> Answer:
    """Generate an audience-specific summary."""
    session = get_completed_session(state, user, body.scan_id)
    with llm_errors("summarize"):
        return answer(make_qa(body.backend).summarize(session, audience=body.audience))


@router.post("/explain")
async def explain_finding(
    body: ExplainIn,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> Answer:
    """Explain a specific finding."""
    session = get_completed_session(state, user, body.scan_id)
    with llm_errors("explain"):
        return answer(make_qa(body.backend).explain_finding(session, body.finding_id))


@router.post("/remediation-plan")
async def remediation_plan(
    body: RemediationIn,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> Answer:
    session = get_completed_session(state, user, body.scan_id)
    with llm_errors("remediation plan"):
        return answer(
            make_qa(body.backend).remediation_plan(session, format=body.format)
        )


@router.post("/test-cases")
async def generate_test_cases(
    body: TestCasesIn,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> Answer:
    """Generate CI security test cases from findings."""
    session = get_completed_session(state, user, body.scan_id)
    with llm_errors("test cases"):
        return answer(
            make_qa(body.backend).generate_test_cases(session, framework=body.framework)
        )


@router.post("/mitigations")
async def suggest_mitigations(
    body: MitigationsIn,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> Answer:
    """Suggest code-level mitigations for findings."""
    session = get_completed_session(state, user, body.scan_id)
    with llm_errors("mitigations"):
        return answer(
            make_qa(body.backend).suggest_mitigations(session, stack=body.stack)
        )


@router.post("/filter-findings")
async def filter_findings(
    body: FilterIn,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> Answer:
    """Filter and explain findings matching a query."""
    session = get_completed_session(state, user, body.scan_id)
    with llm_errors("filter findings"):
        return answer(make_qa(body.backend).filter_findings(session, body.criteria))
