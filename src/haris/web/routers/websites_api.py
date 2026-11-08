from fastapi import Depends

from ...auth.middleware import require_user
from ...auth.models import User
from ..access import visible_owner
from ..routing import api_router
from ..schemas.sites import DashboardSummary, SeverityTrends, Website, WebsiteScan
from ..state import AppState, get_state

router = api_router("scans:read", tags=["websites"])


@router.get("/dashboard/summary")
async def dashboard_summary(
    user: User = Depends(require_user), state: AppState = Depends(get_state)
) -> DashboardSummary:
    return DashboardSummary.model_validate(
        state.store.dashboard_summary(visible_owner(state, user))
    )


@router.get("/websites")
async def list_websites(
    user: User = Depends(require_user), state: AppState = Depends(get_state)
) -> list[Website]:
    return [
        Website.model_validate(w)
        for w in state.store.list_websites(visible_owner(state, user))
    ]


@router.get("/websites/{hostname}/scans")
async def website_scans(
    hostname: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> list[WebsiteScan]:
    rows = state.store.get_scans_for_hostname(hostname, visible_owner(state, user))
    return [WebsiteScan.model_validate(r) for r in rows]


@router.get("/websites/{hostname}/trends")
async def website_trends(
    hostname: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> SeverityTrends:
    return SeverityTrends.model_validate(
        state.store.get_severity_trends(hostname, visible_owner(state, user))
    )
