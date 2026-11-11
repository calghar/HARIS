from pathlib import Path

import pytest

from haris.auth.service import AuthService
from haris.db.store import ScanStore


@pytest.fixture()
def auth_service(tmp_path: Path) -> AuthService:
    db_path = tmp_path / "haris.db"
    ScanStore(db_path)
    return AuthService(db_path)


def test_list_user_sessions_marks_current_and_revoke_by_hash(auth_service):
    user = auth_service.create_user("rae@example.com", "pass")
    current = auth_service.create_session(user.user_id)
    other = auth_service.create_session(user.user_id)

    listed = {
        s["token_hash"]: s
        for s in auth_service.list_user_sessions(user.user_id, current.token)
    }

    assert len(listed) == 2
    assert sum(s["is_current"] for s in listed.values()) == 1
    other_hash = next(h for h, s in listed.items() if not s["is_current"])
    assert not auth_service.revoke_session_by_hash("someone-else", other_hash)
    assert auth_service.revoke_session_by_hash(user.user_id, other_hash)
    assert auth_service.get_session(other.token) is None
    assert auth_service.get_session(current.token) is not None
