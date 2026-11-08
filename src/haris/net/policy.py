import os
from collections.abc import Mapping

from pydantic import BaseModel

ALLOW_PRIVATE_ENV = "HARIS_ALLOW_PRIVATE_TARGETS"


class NetworkPolicy(BaseModel):
    """Per-scan network settings that are not part of the target's scope."""

    allow_private: bool = False
    timeout_s: float = 30.0
    verify_tls: bool = True
    max_body_bytes: int = 2 * 1024 * 1024
    log_capacity: int = 5000

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "NetworkPolicy":
        """Server-side policy: private targets only when the env flag is ``true``."""
        env = os.environ if environ is None else environ
        return cls(allow_private=env.get(ALLOW_PRIVATE_ENV, "").lower() == "true")
