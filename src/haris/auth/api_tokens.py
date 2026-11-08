import secrets
import uuid
from datetime import UTC, datetime, timedelta

from ..db.api_tokens import ApiTokenRecord, ApiTokenRepository
from .database import now_iso
from .tokens import hash_token

TOKEN_PREFIX = "haris_pat_"
DISPLAY_PREFIX_LENGTH = 12
SCOPES = ("scans:read", "scans:write", "targets:write", "admin")
DEFAULT_EXPIRY_DAYS = 90
MAX_EXPIRY_DAYS = 365
TOKEN_BYTES = 32


class ApiTokenService:
    def __init__(self, repo: ApiTokenRepository) -> None:
        self._repo = repo

    def create(
        self,
        user_id: str,
        name: str,
        scopes: list[str],
        expires_in_days: int = DEFAULT_EXPIRY_DAYS,
    ) -> tuple[ApiTokenRecord, str]:
        """Return the stored record and the plaintext token (never stored)."""
        if not 1 <= expires_in_days <= MAX_EXPIRY_DAYS:
            raise ValueError(f"expires_in_days must be 1..{MAX_EXPIRY_DAYS}")
        unknown = set(scopes) - set(SCOPES)
        if unknown or not scopes:
            raise ValueError(f"scopes must be a non-empty subset of {SCOPES}")
        token = TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)
        expires = datetime.now(UTC) + timedelta(days=expires_in_days)
        record = ApiTokenRecord(
            token_id=uuid.uuid4().hex,
            user_id=user_id,
            name=name,
            token_prefix=token[:DISPLAY_PREFIX_LENGTH],
            scopes=sorted(set(scopes)),
            created_at=now_iso(),
            expires_at=expires.isoformat(timespec="seconds"),
        )
        self._repo.insert(record, hash_token(token))
        return record, token

    def authenticate(self, token: str) -> ApiTokenRecord | None:
        """The live record for *token*, or None when unknown, revoked or expired."""
        if not token.startswith(TOKEN_PREFIX):
            return None
        record = self._repo.get_by_hash(hash_token(token))
        now = now_iso()
        if record is None or record.revoked_at or record.expires_at <= now:
            return None
        self._repo.touch(record.token_id, now)
        return record

    def list_for_user(self, user_id: str) -> list[ApiTokenRecord]:
        return self._repo.list_for_user(user_id)

    def revoke(self, token_id: str, user_id: str) -> bool:
        return self._repo.revoke(token_id, user_id, now_iso())
