import os
import secrets
from pathlib import Path

from pydantic import BaseModel, Field

from ..auth.config import env_flag


class WebSettings(BaseModel):
    db_path: Path = Path("data/HARIS.db")
    reports_dir: Path = Path("reports")
    log_dir: Path = Path("data/logs")
    secret_key: str = Field(default_factory=lambda: secrets.token_hex(32))
    force_https: bool = False
    share_scans_org_wide: bool = False

    @classmethod
    def from_env(cls) -> "WebSettings":
        settings = cls(
            force_https=env_flag("HARIS_FORCE_HTTPS"),
            share_scans_org_wide=env_flag("HARIS_SHARE_SCANS_ORG_WIDE"),
        )
        if secret := os.environ.get("HARIS_SECRET_KEY"):
            settings.secret_key = secret
        return settings
