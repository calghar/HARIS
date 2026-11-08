import os
import secrets
from pathlib import Path

from pydantic import BaseModel, Field

from ..auth.config import env_flag

TARGET_ALLOWLIST_ENV = "HARIS_TARGET_ALLOWLIST"
MAX_CONCURRENT_SCANS_ENV = "HARIS_MAX_CONCURRENT_SCANS"
DEFAULT_MAX_CONCURRENT_SCANS = 2


def _csv(raw: str) -> list[str]:
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


class WebSettings(BaseModel):
    db_path: Path = Path("data/HARIS.db")
    reports_dir: Path = Path("reports")
    log_dir: Path = Path("data/logs")
    secret_key: str = Field(default_factory=lambda: secrets.token_hex(32))
    force_https: bool = False
    share_scans_org_wide: bool = False
    target_allowlist: list[str] = Field(default_factory=list)
    max_concurrent_scans: int = Field(default=DEFAULT_MAX_CONCURRENT_SCANS, ge=1)

    @classmethod
    def from_env(cls) -> "WebSettings":
        settings = cls(
            force_https=env_flag("HARIS_FORCE_HTTPS"),
            share_scans_org_wide=env_flag("HARIS_SHARE_SCANS_ORG_WIDE"),
            target_allowlist=_csv(os.environ.get(TARGET_ALLOWLIST_ENV, "")),
            max_concurrent_scans=int(
                os.environ.get(MAX_CONCURRENT_SCANS_ENV, DEFAULT_MAX_CONCURRENT_SCANS)
            ),
        )
        if secret := os.environ.get("HARIS_SECRET_KEY"):
            settings.secret_key = secret
        return settings
