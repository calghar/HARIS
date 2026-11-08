from typing import Literal

from pydantic import BaseModel, Field

from ...auth.api_tokens import DEFAULT_EXPIRY_DAYS, MAX_EXPIRY_DAYS

Scope = Literal["scans:read", "scans:write", "targets:write", "admin"]


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[Scope] = Field(min_length=1)
    expires_in_days: int = Field(default=DEFAULT_EXPIRY_DAYS, ge=1, le=MAX_EXPIRY_DAYS)


class TokenOut(BaseModel):
    token_id: str
    name: str
    token_prefix: str
    scopes: list[str]
    created_at: str
    expires_at: str
    last_used_at: str
    revoked_at: str


class TokenCreated(TokenOut):
    token: str


HOST_PATTERN = r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$"


class TargetCreate(BaseModel):
    host: str = Field(pattern=HOST_PATTERN)


class TargetOut(BaseModel):
    host: str
    proof_token: str
    created_at: str
    verified_at: str
    method: str
    verified: bool
    dns_name: str
    file_path: str
