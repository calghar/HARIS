import json
from pathlib import Path

from haris.db.connection import connect
from haris.db.store import ScanStore
from haris.models import AuthConfig, ScanSession, Scope, Target

_SECRET_HEADER = "Bearer s3cret-credential"
_SECRET_COOKIE = "cookie-s3cret"
_SECRET_USER = "audit-user"
_SECRET_PASSWORD = "p@ss-s3cret"


def _scoped_target() -> Target:
    return Target(
        base_url="https://app.example.com",
        scope=Scope(
            allowed_domains=["app.example.com", "cdn.example.com"],
            excluded_paths=["/logout", r"/admin/.*"],
            max_depth=2,
            rate_limit_rps=1.5,
            max_requests=25,
            allowed_methods=["GET", "POST"],
            follow_redirects=False,
            max_redirect_depth=1,
        ),
        auth=AuthConfig(
            method="header",
            header_name="Authorization",
            header_value=_SECRET_HEADER,
            cookie_name="session",
            cookie_value=_SECRET_COOKIE,
            username=_SECRET_USER,
            password=_SECRET_PASSWORD,
        ),
    )


def test_scope_round_trip_persists_limits_methods_and_redirects(
    tmp_path: Path,
) -> None:
    store = ScanStore(tmp_path / "scope.db")
    target = _scoped_target()
    store.save_session(
        ScanSession(
            session_id="scope-rt",
            target=target,
            started_at="2026-01-01T00:00:00+00:00",
        )
    )
    with connect(store.db_path) as conn:
        row = conn.execute(
            "SELECT target_json FROM scans WHERE session_id = ?",
            ("scope-rt",),
        ).fetchone()
    assert row is not None
    raw = str(row["target_json"])
    payload = json.loads(raw)
    assert set(payload) == {"base_url", "scope"}
    for secret in (
        _SECRET_HEADER,
        _SECRET_COOKIE,
        _SECRET_USER,
        _SECRET_PASSWORD,
    ):
        assert secret not in raw
    loaded = store.load_session("scope-rt")
    assert loaded is not None
    assert loaded.target.scope == target.scope
    assert loaded.target.auth.header_value == ""
    assert loaded.target.auth.cookie_value == ""
    assert loaded.target.auth.password == ""


def test_old_row_without_scope_loads_default_scope(tmp_path: Path) -> None:
    store = ScanStore(tmp_path / "legacy.db")
    store.save_session(
        ScanSession(
            session_id="old-scope",
            target=Target(
                base_url="https://legacy.example.com",
                scope=Scope(excluded_paths=["/only-in-the-writer"]),
            ),
        )
    )
    old = json.dumps({"base_url": "https://legacy.example.com"})
    with connect(store.db_path) as conn:
        conn.execute(
            "UPDATE scans SET target_json = ? WHERE session_id = ?",
            (old, "old-scope"),
        )
    loaded = store.load_session("old-scope")
    assert loaded is not None
    fresh = Target(base_url="https://legacy.example.com")
    assert loaded.target.base_url == fresh.base_url
    assert loaded.target.scope == fresh.scope
