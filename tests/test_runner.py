"""Tests for src.core.runner — shared scan orchestration."""

from unittest.mock import MagicMock, patch

import pytest

from src.core.runner import ScanRunner, build_scan_list
from src.models import Scope, Target


def _make_target(url: str = "https://example.com") -> Target:
    return Target(base_url=url, scope=Scope())


class TestScanRunner:
    def test_run_with_mock_scanners(self):
        target = _make_target()
        runner = ScanRunner(
            target=target,
            profile_name="quick",
        )

        with patch("src.core.runner.all_registered") as mock_reg:
            mock_scanner_cls = MagicMock()
            mock_scanner_instance = MagicMock()
            mock_scanner_instance.name = "header_checks"
            mock_scanner_cls.return_value = mock_scanner_instance

            mock_reg.return_value = {"header_checks": mock_scanner_cls}

            with patch("src.core.runner.get_profile") as mock_profile:
                mock_profile.return_value = MagicMock(
                    scanners=["header_checks"],
                    display_name="Quick",
                    report_intro="Quick scan",
                )

                with patch("src.core.runner.ScanEngine") as mock_engine_cls:
                    mock_session = MagicMock()
                    mock_engine_cls.return_value.run.return_value = mock_session

                    session = runner.run()

                    assert session is mock_session
                    mock_engine_cls.assert_called_once()

    def test_run_no_scanners_raises(self):
        target = _make_target()
        runner = ScanRunner(
            target=target,
            profile_name="quick",
        )

        with patch("src.core.runner.all_registered") as mock_reg:
            mock_reg.return_value = {}

            with patch("src.core.runner.get_profile") as mock_profile:
                mock_profile.return_value = MagicMock(
                    scanners=["nonexistent"],
                )
                with pytest.raises(RuntimeError, match="No scanners available"):
                    runner.run()

    def test_custom_scanner_names(self):
        target = _make_target()
        runner = ScanRunner(
            target=target,
            profile_name="quick",
            scanner_names=["header_checks"],
        )

        with patch("src.core.runner.all_registered") as mock_reg:
            mock_cls = MagicMock()
            mock_cls.return_value = MagicMock(name="header_checks")
            mock_reg.return_value = {"header_checks": mock_cls}

            with patch("src.core.runner.ScanEngine") as mock_engine_cls:
                mock_engine_cls.return_value.run.return_value = MagicMock()
                runner.run()

                call_kwargs = mock_engine_cls.call_args
                scanners = call_kwargs.kwargs.get(
                    "scanners", call_kwargs.args[0] if call_kwargs.args else []
                )
                assert len(scanners) == 1


class TestBuildScanList:
    def test_merge_memory_and_db(self):
        memory = {
            "scan1": {
                "scan_id": "scan1",
                "target_url": "https://a.com",
                "profile": "quick",
                "status": "running",
                "started_at": "2026-01-02",
                "finished_at": None,
                "session": None,
                "error": None,
            },
        }

        mock_store = MagicMock()
        mock_store.list_sessions.return_value = [
            {
                "session_id": "scan2",
                "target_url": "https://b.com",
                "profile_name": "full",
                "started_at": "2026-01-01",
                "risk_posture": "high",
                "finding_count": 5,
            },
        ]

        result = build_scan_list(memory, mock_store)
        assert len(result) == 2
        ids = {r["scan_id"] for r in result}
        assert ids == {"scan1", "scan2"}

    def test_deduplicates_by_id(self):
        memory = {
            "scan1": {
                "scan_id": "scan1",
                "target_url": "https://a.com",
                "profile": "quick",
                "status": "completed",
                "started_at": "2026-01-01",
                "finished_at": None,
                "session": None,
                "error": None,
            },
        }

        mock_store = MagicMock()
        mock_store.list_sessions.return_value = [
            {
                "session_id": "scan1",
                "target_url": "https://a.com",
                "profile_name": "quick",
                "started_at": "2026-01-01",
                "risk_posture": "low",
                "finding_count": 0,
            },
        ]

        result = build_scan_list(memory, mock_store)
        assert len(result) == 1

    def test_sorted_by_start_time(self):
        memory = {
            "old": {
                "scan_id": "old",
                "target_url": "https://a.com",
                "status": "completed",
                "started_at": "2026-01-01",
                "session": None,
            },
            "new": {
                "scan_id": "new",
                "target_url": "https://b.com",
                "status": "completed",
                "started_at": "2026-01-03",
                "session": None,
            },
        }

        mock_store = MagicMock()
        mock_store.list_sessions.return_value = []

        result = build_scan_list(memory, mock_store)
        assert result[0]["scan_id"] == "new"
        assert result[1]["scan_id"] == "old"

    def test_db_error_returns_memory_only(self):
        memory = {
            "scan1": {
                "scan_id": "scan1",
                "target_url": "https://a.com",
                "status": "running",
                "started_at": "2026-01-01",
                "session": None,
            },
        }

        mock_store = MagicMock()
        mock_store.list_sessions.side_effect = Exception("DB error")

        result = build_scan_list(memory, mock_store)
        assert len(result) == 1

    def test_empty(self):
        mock_store = MagicMock()
        mock_store.list_sessions.return_value = []

        result = build_scan_list({}, mock_store)
        assert result == []
