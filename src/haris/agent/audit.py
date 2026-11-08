import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..llm.redaction import redact

LOG_CAP = 500
DIGEST_FIELDS = frozenset({"digest"})


def digest(text: str) -> str:
    return hashlib.sha256(redact(text).encode()).hexdigest()


def _clean(value: str, *, cap: bool, secrets: list[str]) -> str:
    cleaned = "".join(ch for ch in redact(value) if ch >= " " or ch in "\t")
    for secret in secrets:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned[:LOG_CAP] if cap else cleaned


def _redact(value: object, key: str, secrets: list[str]) -> object:
    if isinstance(value, str):
        return _clean(value, cap=key not in DIGEST_FIELDS, secrets=secrets)
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k), secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item, "", secrets) for item in value]
    return value


class AuditLog:
    """Append-only JSONL. Each record is redacted before it is written."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")
        self._lock = threading.Lock()
        self._secrets: list[str] = []

    def redact_secret(self, secret: str) -> None:
        """Drop this exact string from every later record."""
        if secret and secret not in self._secrets:
            self._secrets.append(secret)

    def write(self, kind: str, **fields: object) -> None:
        record: dict[str, Any] = {
            "kind": kind,
            "ts": datetime.now(UTC).isoformat(),
            **{
                key: _redact(value, key, self._secrets) for key, value in fields.items()
            },
        }
        line = json.dumps(record, sort_keys=True, default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        with self._lock:
            self._fh.close()
