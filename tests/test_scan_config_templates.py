"""Tests for ScanConfigTemplate CRUD operations in ScanStore."""

from __future__ import annotations

import sqlite3

import pytest

from src.db.store import ScanStore
from src.models import RiskPosture, ScanSession, Target
from src.models.scan_config_template import ScanConfigTemplate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_template(
    template_id: str = "tpl-001",
    name: str = "Test Template",
    *,
    is_default: bool = False,
    profile: str = "quick",
    description: str = "A test scan config template.",
    scanner_options: dict | None = None,
    tags: list[str] | None = None,
) -> ScanConfigTemplate:
    return ScanConfigTemplate(
        template_id=template_id,
        name=name,
        description=description,
        profile=profile,
        rate_limit_rps=10.0,
        max_requests=10_000,
        excluded_paths=["/admin", "/internal"],
        auth_method="none",
        report_formats=["markdown", "json"],
        llm_enrichment=False,
        llm_backend="",
        scanner_options=scanner_options if scanner_options is not None else {},
        tags=tags if tags is not None else ["test"],
        is_default=is_default,
        created_at="2025-01-01T00:00:00",
        updated_at="2025-01-01T00:00:00",
    )


def _make_session(
    session_id: str = "test-001",
    target_url: str = "https://example.com",
    template_id: str = "",
) -> ScanSession:
    target = Target(base_url=target_url)
    return ScanSession(
        session_id=session_id,
        target=target,
        started_at="2025-01-01T00:00:00",
        finished_at="2025-01-01T00:05:00",
        profile_name="quick",
        risk_posture=RiskPosture.MODERATE,
        template_id=template_id,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSaveAndLoadTemplate:
    def test_save_and_load_template(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        tpl = _make_template(
            template_id="tpl-load-001",
            name="Load Test",
            description="Verify all fields round-trip correctly.",
            profile="full",
            scanner_options={
                "nuclei": {"tags": ["cve"], "rate_limit": 50},
            },
            tags=["ci", "smoke"],
        )
        tpl_with_extras = tpl.model_copy(
            update={
                "rate_limit_rps": 7.5,
                "max_requests": 25_000,
                "excluded_paths": ["/skip-me"],
                "auth_method": "header",
                "report_formats": ["html"],
                "llm_enrichment": True,
                "llm_backend": "anthropic",
            }
        )

        store.save_scan_config_template(tpl_with_extras)
        loaded = store.get_scan_config_template("tpl-load-001")

        assert loaded is not None
        assert loaded.template_id == "tpl-load-001"
        assert loaded.name == "Load Test"
        assert loaded.description == "Verify all fields round-trip correctly."
        assert loaded.profile == "full"
        assert loaded.rate_limit_rps == 7.5
        assert loaded.max_requests == 25_000
        assert loaded.excluded_paths == ["/skip-me"]
        assert loaded.auth_method == "header"
        assert loaded.report_formats == ["html"]
        assert loaded.llm_enrichment is True
        assert loaded.llm_backend == "anthropic"
        assert loaded.tags == ["ci", "smoke"]
        assert loaded.scanner_options == {
            "nuclei": {"tags": ["cve"], "rate_limit": 50}
        }
        assert loaded.created_at == "2025-01-01T00:00:00"
        assert loaded.updated_at == "2025-01-01T00:00:00"

    def test_load_nonexistent_template_returns_none(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        result = store.get_scan_config_template("does-not-exist")
        assert result is None


class TestListTemplates:
    def test_list_templates_ordering_default_first_then_alphabetical(
        self, tmp_path
    ):
        store = ScanStore(tmp_path / "test.db")
        # Clear out seeded defaults so we control the full list.
        with store._connect() as conn:
            conn.execute("DELETE FROM scan_config_templates")
            conn.commit()

        store.save_scan_config_template(
            _make_template("tpl-c", "Zeta Scan", is_default=False)
        )
        store.save_scan_config_template(
            _make_template("tpl-a", "Alpha Scan", is_default=False)
        )
        store.save_scan_config_template(
            _make_template("tpl-b", "Beta Scan", is_default=True)
        )

        templates = store.list_scan_config_templates()

        assert len(templates) == 3
        # Default comes first regardless of alphabetical position.
        assert templates[0]["name"] == "Beta Scan"
        assert templates[0]["is_default"] is True
        # Non-defaults are alphabetical.
        assert templates[1]["name"] == "Alpha Scan"
        assert templates[2]["name"] == "Zeta Scan"

    def test_list_templates_returns_empty_when_none(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        with store._connect() as conn:
            conn.execute("DELETE FROM scan_config_templates")
            conn.commit()

        result = store.list_scan_config_templates()
        assert result == []

    def test_list_templates_includes_expected_dict_keys(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        with store._connect() as conn:
            conn.execute("DELETE FROM scan_config_templates")
            conn.commit()

        store.save_scan_config_template(_make_template())

        templates = store.list_scan_config_templates()
        assert len(templates) == 1

        entry = templates[0]
        expected_keys = {
            "template_id",
            "name",
            "description",
            "profile",
            "rate_limit_rps",
            "max_requests",
            "scanner_options",
            "tags",
            "is_default",
            "created_at",
            "updated_at",
        }
        assert expected_keys.issubset(entry.keys())


class TestDeleteTemplate:
    def test_delete_template_removes_it(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        tpl = _make_template("tpl-del-001")
        store.save_scan_config_template(tpl)

        assert store.get_scan_config_template("tpl-del-001") is not None

        deleted = store.delete_scan_config_template("tpl-del-001")

        assert deleted is True
        assert store.get_scan_config_template("tpl-del-001") is None

    def test_delete_nonexistent_template_returns_false(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        result = store.delete_scan_config_template("ghost-template")
        assert result is False

    def test_delete_template_does_not_affect_others(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        with store._connect() as conn:
            conn.execute("DELETE FROM scan_config_templates")
            conn.commit()

        store.save_scan_config_template(_make_template("tpl-keep", "Keep Me"))
        store.save_scan_config_template(_make_template("tpl-gone", "Gone"))

        store.delete_scan_config_template("tpl-gone")

        templates = store.list_scan_config_templates()
        names = [t["name"] for t in templates]
        assert "Keep Me" in names
        assert "Gone" not in names


class TestSetDefaultTemplate:
    def test_set_default_makes_only_one_default(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        with store._connect() as conn:
            conn.execute("DELETE FROM scan_config_templates")
            conn.commit()

        store.save_scan_config_template(
            _make_template("tpl-x", "Template X", is_default=True)
        )
        store.save_scan_config_template(
            _make_template("tpl-y", "Template Y", is_default=False)
        )

        # Both saved; X is default.
        assert store.get_scan_config_template("tpl-x").is_default is True
        assert store.get_scan_config_template("tpl-y").is_default is False

        # Switch default to Y.
        store.set_default_scan_config_template("tpl-y")

        reloaded_x = store.get_scan_config_template("tpl-x")
        reloaded_y = store.get_scan_config_template("tpl-y")
        assert reloaded_x.is_default is False
        assert reloaded_y.is_default is True

    def test_set_default_clears_all_previous_defaults(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        with store._connect() as conn:
            conn.execute("DELETE FROM scan_config_templates")
            conn.commit()

        for i in range(1, 4):
            store.save_scan_config_template(
                _make_template(f"tpl-{i}", f"Template {i}")
            )

        # Set each in turn and check uniqueness of default.
        for target_id in ["tpl-1", "tpl-2", "tpl-3"]:
            store.set_default_scan_config_template(target_id)
            templates = store.list_scan_config_templates()
            defaults = [t for t in templates if t["is_default"]]
            assert len(defaults) == 1
            assert defaults[0]["template_id"] == target_id


class TestGetDefaultTemplate:
    def test_get_default_returns_default_template(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        with store._connect() as conn:
            conn.execute("DELETE FROM scan_config_templates")
            conn.commit()

        store.save_scan_config_template(
            _make_template("tpl-d", "The Default", is_default=True)
        )
        store.save_scan_config_template(
            _make_template("tpl-nd", "Not Default", is_default=False)
        )

        default = store.get_default_scan_config_template()

        assert default is not None
        assert default.template_id == "tpl-d"
        assert default.name == "The Default"
        assert default.is_default is True

    def test_get_default_returns_none_when_no_default(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        with store._connect() as conn:
            conn.execute("DELETE FROM scan_config_templates")
            conn.commit()

        store.save_scan_config_template(
            _make_template("tpl-nd", "No Default", is_default=False)
        )

        result = store.get_default_scan_config_template()
        assert result is None

    def test_get_default_returns_none_when_table_empty(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        with store._connect() as conn:
            conn.execute("DELETE FROM scan_config_templates")
            conn.commit()

        result = store.get_default_scan_config_template()
        assert result is None


class TestTemplateLinkedToScan:
    def test_session_with_template_id_persists(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        tpl = _make_template("tpl-linked-001", "Linked Template")
        store.save_scan_config_template(tpl)

        session = _make_session(
            session_id="scan-linked-001",
            template_id="tpl-linked-001",
        )
        store.save_session(session)

        loaded = store.load_session("scan-linked-001")
        assert loaded is not None
        assert loaded.template_id == "tpl-linked-001"

    def test_session_without_template_id_has_empty_string(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        session = _make_session(session_id="scan-no-tpl", template_id="")
        store.save_session(session)

        loaded = store.load_session("scan-no-tpl")
        assert loaded is not None
        assert loaded.template_id == ""

    def test_template_id_preserved_in_list_sessions(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        tpl = _make_template("tpl-list-link", "List Link Template")
        store.save_scan_config_template(tpl)

        session = _make_session(
            session_id="scan-list-link",
            template_id="tpl-list-link",
        )
        store.save_session(session)

        sessions = store.list_sessions()
        match = next(
            (s for s in sessions if s["session_id"] == "scan-list-link"), None
        )
        assert match is not None
        assert match["template_id"] == "tpl-list-link"


class TestScannerOptionsRoundtrip:
    def test_nested_dicts_survive_json_roundtrip(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        complex_options = {
            "nuclei": {
                "tags": ["cve", "misconfig", "exposure"],
                "severity": ["critical", "high"],
                "rate_limit": 150,
                "timeout": 30,
            },
            "nikto": {
                "tuning": "1234abcd",
                "plugins": ["@@DEFAULT", "shellshock"],
                "timeout": 60,
            },
            "wapiti": {
                "scope": "domain",
                "modules": "all",
                "max_scan_time": 900,
                "max_links": 1000,
                "extra": {
                    "nested_flag": True,
                    "nested_list": [1, 2, 3],
                },
            },
            "nmap": {
                "ports": "80,443,8080,8443",
                "script_categories": ["default", "safe", "vuln"],
                "timeout": 120,
            },
        }

        tpl = _make_template(
            "tpl-complex-opts",
            "Complex Options Template",
            scanner_options=complex_options,
        )
        store.save_scan_config_template(tpl)

        loaded = store.get_scan_config_template("tpl-complex-opts")
        assert loaded is not None
        assert loaded.scanner_options == complex_options

    def test_empty_scanner_options_roundtrip(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        tpl = _make_template("tpl-empty-opts", scanner_options={})
        store.save_scan_config_template(tpl)

        loaded = store.get_scan_config_template("tpl-empty-opts")
        assert loaded is not None
        assert loaded.scanner_options == {}

    def test_lists_in_scanner_options_preserve_order(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        ordered_options = {
            "nuclei": {"tags": ["z-tag", "a-tag", "m-tag"]},
        }
        tpl = _make_template(
            "tpl-ordered", scanner_options=ordered_options
        )
        store.save_scan_config_template(tpl)

        loaded = store.get_scan_config_template("tpl-ordered")
        assert loaded is not None
        assert loaded.scanner_options["nuclei"]["tags"] == [
            "z-tag", "a-tag", "m-tag"
        ]


class TestSchemaV4Migration:
    def test_fresh_db_has_scan_config_templates_table(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")

        with store._connect() as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }

        assert "scan_config_templates" in tables

    def test_fresh_db_has_template_id_column_on_scans(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")

        with store._connect() as conn:
            cols = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(scans)"
                ).fetchall()
            }

        assert "template_id" in cols

    def test_schema_version_is_4(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")

        with store._connect() as conn:
            version = conn.execute(
                "SELECT version FROM schema_version LIMIT 1"
            ).fetchone()["version"]

        assert version == 4

    def test_scan_config_templates_schema_has_expected_columns(
        self, tmp_path
    ):
        store = ScanStore(tmp_path / "test.db")

        with store._connect() as conn:
            cols = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(scan_config_templates)"
                ).fetchall()
            }

        expected = {
            "template_id",
            "name",
            "description",
            "profile",
            "rate_limit_rps",
            "max_requests",
            "excluded_paths",
            "auth_method",
            "report_formats",
            "llm_enrichment",
            "llm_backend",
            "scanner_options",
            "tags",
            "is_default",
            "created_at",
            "updated_at",
        }
        assert expected.issubset(cols)


class TestSeedDefaultTemplates:
    def test_fresh_db_seeds_five_built_in_templates(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")

        templates = store.list_scan_config_templates()
        assert len(templates) == 5

    def test_seeded_template_ids_are_builtin_prefixed(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")

        templates = store.list_scan_config_templates()
        ids = {t["template_id"] for t in templates}
        assert ids == {
            "builtin-01",
            "builtin-02",
            "builtin-03",
            "builtin-04",
            "builtin-05",
        }

    def test_only_quick_surface_scan_is_default(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")

        templates = store.list_scan_config_templates()
        defaults = [t for t in templates if t["is_default"]]
        assert len(defaults) == 1
        assert defaults[0]["template_id"] == "builtin-01"
        assert defaults[0]["name"] == "Quick Surface Scan"

    def test_seed_does_not_run_twice(self, tmp_path):
        """Initialising a second store against the same DB must not duplicate."""
        store1 = ScanStore(tmp_path / "shared.db")
        store2 = ScanStore(tmp_path / "shared.db")

        templates = store2.list_scan_config_templates()
        assert len(templates) == 5

    def test_seeded_templates_have_expected_profiles(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")

        templates = {t["template_id"]: t for t in store.list_scan_config_templates()}
        assert templates["builtin-01"]["profile"] == "quick"
        assert templates["builtin-02"]["profile"] == "pre-launch"
        assert templates["builtin-03"]["profile"] == "full"
        assert templates["builtin-04"]["profile"] == "regression"
        assert templates["builtin-05"]["profile"] == "compliance"


class TestListSessionsPaginatedTemplateFilter:
    def _seed_sessions(self, store: ScanStore) -> None:
        """Save three sessions — two linked to builtin-01, one unlinked."""
        for i, tpl_id in enumerate(
            ["builtin-01", "builtin-01", "builtin-02"]
        ):
            session = _make_session(
                session_id=f"filter-scan-{i:03d}",
                target_url="https://example.com",
                template_id=tpl_id,
            )
            store.save_session(session)

    def test_template_filter_returns_only_matching_sessions(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        self._seed_sessions(store)

        results, total = store.list_sessions_paginated(
            template_id="builtin-01"
        )

        assert total == 2
        assert all(r["template_id"] == "builtin-01" for r in results)

    def test_template_filter_no_match_returns_empty(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        self._seed_sessions(store)

        results, total = store.list_sessions_paginated(
            template_id="builtin-99"
        )

        assert total == 0
        assert results == []

    def test_template_filter_pagination_respects_per_page(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        # Save 4 sessions linked to the same template.
        for i in range(4):
            store.save_session(
                _make_session(
                    session_id=f"page-scan-{i:03d}",
                    template_id="builtin-01",
                )
            )

        page1, total = store.list_sessions_paginated(
            template_id="builtin-01", page=1, per_page=2
        )
        page2, _ = store.list_sessions_paginated(
            template_id="builtin-01", page=2, per_page=2
        )

        assert total == 4
        assert len(page1) == 2
        assert len(page2) == 2
        # No session should appear in both pages.
        ids_page1 = {r["session_id"] for r in page1}
        ids_page2 = {r["session_id"] for r in page2}
        assert ids_page1.isdisjoint(ids_page2)

    def test_no_template_filter_returns_all_sessions(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        self._seed_sessions(store)

        _, total = store.list_sessions_paginated()
        assert total == 3

    def test_template_filter_result_includes_template_id_field(
        self, tmp_path
    ):
        store = ScanStore(tmp_path / "test.db")
        self._seed_sessions(store)

        results, _ = store.list_sessions_paginated(template_id="builtin-02")

        assert len(results) == 1
        assert "template_id" in results[0]
        assert results[0]["template_id"] == "builtin-02"


class TestUpsertTemplate:
    def test_save_overwrites_existing_template(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        tpl = _make_template("tpl-upsert", "Original Name", profile="quick")
        store.save_scan_config_template(tpl)

        updated = tpl.model_copy(
            update={"name": "Updated Name", "profile": "full"}
        )
        store.save_scan_config_template(updated)

        loaded = store.get_scan_config_template("tpl-upsert")
        assert loaded is not None
        assert loaded.name == "Updated Name"
        assert loaded.profile == "full"

    def test_save_template_with_boolean_llm_enrichment(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        tpl_on = _make_template("tpl-llm-on").model_copy(
            update={"llm_enrichment": True}
        )
        tpl_off = _make_template("tpl-llm-off").model_copy(
            update={"llm_enrichment": False}
        )

        store.save_scan_config_template(tpl_on)
        store.save_scan_config_template(tpl_off)

        assert store.get_scan_config_template("tpl-llm-on").llm_enrichment is True
        assert store.get_scan_config_template("tpl-llm-off").llm_enrichment is False
