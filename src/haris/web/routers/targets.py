from fastapi import Depends, HTTPException, Path, Request, Response

from ...auth.middleware import get_auth_service, require_user
from ...auth.models import AuditAction, AuditEvent, User
from ...auth.service import AuthService
from ...db.targets import AuthorizedTarget
from ..routing import api_router
from ..schemas.access import HOST_PATTERN, TargetCreate, TargetOut
from ..state import AppState, get_state
from ..targets import DNS_LABEL, WELL_KNOWN_PATH

router = api_router("targets:write", prefix="/targets", tags=["targets"])

HostPath = Path(pattern=HOST_PATTERN)


def _out(state: AppState, row: AuthorizedTarget) -> TargetOut:
    return TargetOut(
        **row.model_dump(exclude={"user_id"}),
        verified=state.targets.is_current(row),
        dns_name=f"{DNS_LABEL}.{row.host}",
        file_path=WELL_KNOWN_PATH,
    )


@router.post(
    "",
    responses={400: {"description": "Host rejected by the SSRF guard"}},
)
async def request_target(
    body: TargetCreate,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> TargetOut:
    """Return the proof token for (user, host), creating it on first request."""
    host = body.host.lower().rstrip(".")
    state.targets.vet_host(host)
    return _out(state, state.targets.issue(user.user_id, host))


@router.get("")
async def list_targets(
    user: User = Depends(require_user), state: AppState = Depends(get_state)
) -> list[TargetOut]:
    return [_out(state, r) for r in state.targets.list_for_user(user.user_id)]


@router.post(
    "/{host}/verify",
    responses={400: {"description": "Host rejected by the SSRF guard"}},
)
async def verify_target(
    request: Request,
    host: str = HostPath,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> TargetOut:
    """Check DNS and file proof for the exact host; `verified` tells the result."""
    row = state.targets.verify(user.user_id, host)
    out = _out(state, row)
    if out.verified:
        auth_service.log_audit(
            AuditEvent(
                user_id=user.user_id,
                user_email=user.email,
                action=AuditAction.TARGET_VERIFIED,
                resource_id=row.host,
                resource_type="target",
                details={"method": row.method},
                ip_address=request.client.host if request.client else "",
            )
        )
    return out


@router.delete("/{host}", status_code=204)
async def delete_target(
    host: str = HostPath,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> Response:
    if not state.targets.remove(user.user_id, host):
        raise HTTPException(status_code=404, detail="Target not found")
    return Response(status_code=204)
