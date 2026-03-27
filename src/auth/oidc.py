import logging
from typing import Any, cast

from pydantic import BaseModel
from starlette.requests import Request
from starlette.responses import Response

from .models import UserRole

logger = logging.getLogger(__name__)


class OIDCConfig(BaseModel):
    enabled: bool = False
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""  # loaded from HARIS_OIDC_CLIENT_SECRET env var
    scopes: list[str] = ["openid", "email", "profile"]
    role_claim: str = "haris_role"
    admin_role_value: str = "haris-admin"


class OIDCClient:
    """Thin wrapper around authlib Starlette OAuth client.

    Uses server_metadata_url (/.well-known/openid-configuration) for
    auto-discovery -- no hardcoded endpoint URLs needed.
    """

    def __init__(self, config: OIDCConfig) -> None:
        self._config = config
        self._oauth: Any = None  # authlib.integrations.starlette_client.OAuth

    def is_enabled(self) -> bool:
        return (
            self._config.enabled
            and bool(self._config.issuer)
            and bool(self._config.client_id)
        )

    def _get_oauth(self) -> Any:
        if self._oauth is None:
            try:
                from authlib.integrations.starlette_client import OAuth
            except ImportError as err:
                raise RuntimeError(
                    "authlib is required for OIDC. "
                    "Install it: pip install authlib httpx"
                ) from err
            cfg = self._config
            self._oauth = OAuth()
            self._oauth.register(
                name="oidc",
                server_metadata_url=(
                    f"{cfg.issuer.rstrip('/')}/.well-known/openid-configuration"
                ),
                client_id=cfg.client_id,
                client_secret=cfg.client_secret,
                client_kwargs={
                    "scope": " ".join(cfg.scopes),
                    "code_challenge_method": "S256",  # PKCE
                },
            )
        return self._oauth

    async def authorize_redirect(self, request: Request, redirect_uri: str) -> Response:
        """Generate redirect response to the OIDC authorization endpoint."""
        return cast(
            Response,
            await self._get_oauth().oidc.authorize_redirect(request, redirect_uri),
        )

    async def handle_callback(self, request: Request) -> dict[str, Any]:
        """Exchange authorization code for tokens and return userinfo dict.

        Returns a dict containing at minimum: sub, email,
        name (or preferred_username).
        """
        token = await self._get_oauth().oidc.authorize_access_token(request)
        userinfo: dict[str, Any] = token.get("userinfo") or {}
        if not userinfo:
            userinfo = await self._get_oauth().oidc.userinfo(token=token)
        return dict(userinfo)

    def extract_role(self, userinfo: dict[str, Any]) -> UserRole:
        """Map OIDC claims to a HARIS UserRole.

        Checks the configured role_claim first, then KeyCloak-style
        realm_access.roles list as a fallback.
        """
        cfg = self._config
        # Direct claim (e.g. custom KeyCloak mapper attribute)
        claim_value = userinfo.get(cfg.role_claim, "")
        if claim_value == cfg.admin_role_value:
            return UserRole.ADMIN
        # KeyCloak realm_access.roles list
        realm_roles: list[str] = userinfo.get("realm_access", {}).get("roles", [])
        if cfg.admin_role_value in realm_roles:
            return UserRole.ADMIN
        return UserRole.USER

    @staticmethod
    def get_display_name(userinfo: dict[str, Any]) -> str:
        return str(
            userinfo.get("name")
            or userinfo.get("preferred_username")
            or userinfo.get("email", "").split("@")[0]
        )
