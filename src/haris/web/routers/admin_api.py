from fastapi import Depends

from ...auth.middleware import get_auth_service
from ...auth.models import UserPublic
from ...auth.service import AuthService
from ..routing import admin_api_router

router = admin_api_router(prefix="/admin", tags=["admin"])


@router.get("/users")
async def list_users(
    auth_service: AuthService = Depends(get_auth_service),
) -> list[UserPublic]:
    return [UserPublic.from_user(u) for u in auth_service.list_users()]
