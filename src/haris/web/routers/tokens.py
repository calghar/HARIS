from fastapi import Depends, HTTPException, Request, Response

from ...auth.api_tokens import ApiTokenService
from ...auth.middleware import get_auth_service, require_user
from ...auth.models import AuditAction, AuditEvent, User
from ...auth.service import AuthService
from ..routing import session_api_router
from ..schemas.access import TokenCreate, TokenCreated, TokenOut
from ..state import AppState, get_state

router = session_api_router(prefix="/tokens", tags=["tokens"])


def _tokens(state: AppState = Depends(get_state)) -> ApiTokenService:
    return state.tokens


def _audit(
    auth_service: AuthService,
    request: Request,
    user: User,
    action: AuditAction,
    token_id: str,
) -> None:
    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=action,
            resource_id=token_id,
            resource_type="api_token",
            ip_address=request.client.host if request.client else "",
        )
    )


@router.post("", status_code=201)
async def create_token(
    request: Request,
    body: TokenCreate,
    user: User = Depends(require_user),
    tokens: ApiTokenService = Depends(_tokens),
    auth_service: AuthService = Depends(get_auth_service),
) -> TokenCreated:
    """Create a token; the plaintext is returned once and never stored."""
    record, plaintext = tokens.create(
        user.user_id, body.name, list(body.scopes), body.expires_in_days
    )
    _audit(auth_service, request, user, AuditAction.TOKEN_CREATED, record.token_id)
    return TokenCreated.model_validate({**record.model_dump(), "token": plaintext})


@router.get("")
async def list_tokens(
    user: User = Depends(require_user), tokens: ApiTokenService = Depends(_tokens)
) -> list[TokenOut]:
    return [
        TokenOut.model_validate(r.model_dump())
        for r in tokens.list_for_user(user.user_id)
    ]


@router.delete(
    "/{token_id}",
    status_code=204,
    responses={404: {"description": "Token not found or already revoked"}},
)
async def revoke_token(
    request: Request,
    token_id: str,
    user: User = Depends(require_user),
    tokens: ApiTokenService = Depends(_tokens),
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    if not tokens.revoke(token_id, user.user_id):
        raise HTTPException(status_code=404, detail="Token not found")
    _audit(auth_service, request, user, AuditAction.TOKEN_REVOKED, token_id)
    return Response(status_code=204)
