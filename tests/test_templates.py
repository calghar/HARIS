from unittest.mock import patch

from src.models.templates import (
    TemplateConfig,
    TemplateMetadata,
    TemplateSource,
    UpdateResult,
)
from src.templates.adapters import (
    ADAPTER_REGISTRY,
    NiktoTemplateAdapter,
    NucleiTemplateAdapter,
    get_adapter,
)
from src.templates.manager import TemplateManager
from src.templates.report import TemplateUpdateReporter
from src.templates.updater import TemplateUpdater

# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestTemplateSource:
    def test_defaults(self):
        src = TemplateSource(name="test", scanner="nuclei")
        assert src.source_type == "git"
        assert src.branch == "main"
        assert src.enabled is True

    def test_all_fields(self):
        src = TemplateSource(
            name="custom",
            scanner="nmap",
            source_type="url",
            url="https://example.com/scripts.tar.gz",
            enabled=False,
        )
        assert src.source_type == "url"
        assert not src.enabled


class TestUpdateResult:
    def test_success(self):
        r = UpdateResult(
            scanner="nuclei",
            source_name="official",
            success=True,
            new_version="abc1234",
            templates_added=100,
        )
        assert r.success
        assert r.error == ""

    def test_failure(self):
        r = UpdateResult(
            scanner="nmap",
            source_name="test",
            success=False,
            error="git clone failed",
        )
        assert not r.success


# ---------------------------------------------------------------------------
# Adapter registry
# ---------------------------------------------------------------------------


class TestAdapterRegistry:
    def test_all_scanners_have_adapters(self):
        for scanner in ["nuclei", "nikto", "nmap", "wapiti"]:
            assert scanner in ADAPTER_REGISTRY

    def test_get_adapter_returns_instance(self):
        adapter = get_adapter("nuclei")
        assert adapter is not None
        assert isinstance(adapter, NucleiTemplateAdapter)

    def test_get_adapter_unknown(self):
        assert get_adapter("unknown_scanner") is None


# ---------------------------------------------------------------------------
# NucleiTemplateAdapter
# ---------------------------------------------------------------------------


class TestNucleiAdapter:
    def test_get_scanner_options_empty_dir(self, tmp_path):
        adapter = NucleiTemplateAdapter()
        opts = adapter.get_scanner_options(tmp_path, [])
        assert opts == {}

    def test_get_scanner_options_with_sources(self, tmp_path):
        # Create a fake template dir
        src_dir = tmp_path / "nuclei" / "official"
        src_dir.mkdir(parents=True)
        (src_dir / "test.yaml").write_text("id: test")

        source = TemplateSource(
            name="official",
            scanner="nuclei",
            source_type="git",
        )
        adapter = NucleiTemplateAdapter()
        opts = adapter.get_scanner_options(tmp_path, [source])
        assert "templates" in opts
        assert str(src_dir) in opts["templates"]

    def test_get_scanner_options_custom_dir(self, tmp_path):
        custom_dir = tmp_path / "nuclei" / "custom"
        custom_dir.mkdir(parents=True)
        (custom_dir / "my_check.yaml").write_text("id: custom")

        adapter = NucleiTemplateAdapter()
        opts = adapter.get_scanner_options(tmp_path, [])
        assert "templates" in opts
        assert str(custom_dir) in opts["templates"]

    def test_list_templates(self, tmp_path):
        tmpl_dir = tmp_path / "templates"
        tmpl_dir.mkdir()
        (tmpl_dir / "a.yaml").write_text("id: a")
        (tmpl_dir / "b.yml").write_text("id: b")
        (tmpl_dir / "readme.md").write_text("not a template")

        adapter = NucleiTemplateAdapter()
        templates = adapter.list_templates(tmpl_dir)
        assert "a.yaml" in templates
        assert "b.yml" in templates
        assert "readme.md" not in templates

    @patch.object(TemplateUpdater, "git_clone_or_pull", return_value=True)
    @patch.object(TemplateUpdater, "get_git_version", return_value="abc1234")
    @patch.object(TemplateUpdater, "count_files", return_value=50)
    def test_update_git_source(self, mock_count, mock_ver, mock_git, tmp_path):
        source = TemplateSource(
            name="official",
            scanner="nuclei",
            source_type="git",
            url="https://example.com/repo.git",
        )
        adapter = NucleiTemplateAdapter()
        result = adapter.update(source, tmp_path / "nuclei" / "official")
        assert result.success
        assert result.new_version == "abc1234"


# ---------------------------------------------------------------------------
# NiktoTemplateAdapter
# ---------------------------------------------------------------------------


class TestNiktoAdapter:
    def test_file_patterns(self):
        adapter = NiktoTemplateAdapter()
        assert adapter.file_patterns == ["db_*"]

    def test_get_scanner_options_returns_empty(self, tmp_path):
        adapter = NiktoTemplateAdapter()
        source = TemplateSource(
            name="nikto-local",
            scanner="nikto",
            source_type="local",
            local_path="/opt/nikto",
        )
        opts = adapter.get_scanner_options(tmp_path, [source])
        assert opts == {}

    def test_update_unsupported_source_type(self, tmp_path):
        adapter = NiktoTemplateAdapter()
        source = TemplateSource(
            name="nikto-url",
            scanner="nikto",
            source_type="url",
        )
        result = adapter.update(source, tmp_path)
        assert not result.success
        assert "Unsupported source_type" in result.error

    @patch("shutil.which", return_value=None)
    def test_update_local_no_git(self, mock_which, tmp_path):
        adapter = NiktoTemplateAdapter()
        source = TemplateSource(
            name="nikto-local",
            scanner="nikto",
            source_type="local",
            local_path=str(tmp_path),
            branch="master",
        )
        result = adapter.update(source, tmp_path)
        assert not result.success
        assert "git is not installed" in result.error

    @patch("shutil.which", return_value="/usr/bin/git")
    @patch.object(TemplateUpdater, "_git_pull", return_value=True)
    @patch.object(TemplateUpdater, "get_git_version", return_value="f1a2b3c")
    def test_update_local_success(
        self,
        mock_ver,
        mock_pull,
        mock_which,
        tmp_path,
    ):
        # Set up a fake nikto directory with program/databases/db_*
        db_dir = tmp_path / "program" / "databases"
        db_dir.mkdir(parents=True)
        (db_dir / "db_tests").write_text("test data")
        (db_dir / "db_outdated").write_text("outdated checks")
        (db_dir / "db_variables").write_text("variables")

        adapter = NiktoTemplateAdapter()
        source = TemplateSource(
            name="nikto-local",
            scanner="nikto",
            source_type="local",
            local_path=str(tmp_path),
            branch="master",
        )
        result = adapter.update(source, tmp_path / "nikto" / "nikto-local")
        assert result.success
        assert result.new_version == "f1a2b3c"
        assert result.templates_added == 3
        assert result.local_path == str(db_dir)

    @patch.object(TemplateUpdater, "git_clone_or_pull", return_value=True)
    @patch.object(TemplateUpdater, "get_git_version", return_value="aaa1111")
    @patch.object(TemplateUpdater, "count_files", return_value=12)
    def test_update_git_source(
        self,
        mock_count,
        mock_ver,
        mock_git,
        tmp_path,
    ):
        adapter = NiktoTemplateAdapter()
        source = TemplateSource(
            name="nikto-remote",
            scanner="nikto",
            source_type="git",
            url="https://github.com/sullo/nikto.git",
            branch="master",
        )
        result = adapter.update(source, tmp_path / "nikto" / "nikto-remote")
        assert result.success
        assert result.new_version == "aaa1111"

    def test_list_templates_db_files(self, tmp_path):
        (tmp_path / "db_tests").write_text("data")
        (tmp_path / "db_variables").write_text("data")
        (tmp_path / "readme.md").write_text("not a db")
        (tmp_path / "config.txt").write_text("not a db")

        adapter = NiktoTemplateAdapter()
        templates = adapter.list_templates(tmp_path)
        assert "db_tests" in templates
        assert "db_variables" in templates
        assert "readme.md" not in templates
        assert "config.txt" not in templates

    def test_update_result_has_local_path(self):
        """Verify UpdateResult model accepts the local_path field."""
        r = UpdateResult(
            scanner="nikto",
            source_name="nikto-local",
            success=True,
            local_path="/opt/nikto/program/databases",
        )
        assert r.local_path == "/opt/nikto/program/databases"


# ---------------------------------------------------------------------------
# TemplateManager
# ---------------------------------------------------------------------------


class TestTemplateManager:
    def test_init_directory(self, tmp_path):
        mgr = TemplateManager(base_dir=tmp_path / "templates")
        mgr.init_directory()
        assert (tmp_path / "templates" / "nuclei" / "custom").is_dir()
        assert (tmp_path / "templates" / "nikto" / "custom").is_dir()
        assert (tmp_path / "templates" / "nmap" / "custom").is_dir()
        assert (tmp_path / "templates" / "wapiti" / "custom").is_dir()

    def test_from_config(self, tmp_path):
        config = TemplateConfig(
            template_dir=str(tmp_path / "templates"),
            sources=[
                TemplateSource(name="t1", scanner="nuclei"),
            ],
        )
        mgr = TemplateManager.from_config(config)
        assert len(mgr.sources) == 1
        assert mgr.sources[0].name == "t1"

    def test_add_source(self):
        mgr = TemplateManager()
        src = TemplateSource(name="new", scanner="nuclei")
        mgr.add_source(src)
        assert len(mgr.sources) == 1

        # Idempotent
        mgr.add_source(src)
        assert len(mgr.sources) == 1

    def test_remove_source(self):
        mgr = TemplateManager(
            sources=[TemplateSource(name="x", scanner="nuclei")],
        )
        assert mgr.remove_source("x")
        assert len(mgr.sources) == 0
        assert not mgr.remove_source("nonexistent")

    def test_metadata_persistence(self, tmp_path):
        mgr = TemplateManager(base_dir=tmp_path)
        mgr.init_directory()

        metadata = {
            "test": TemplateMetadata(
                source_name="test",
                scanner="nuclei",
                version="abc",
                template_count=10,
            ),
        }
        mgr._save_metadata(metadata)

        loaded = mgr._load_metadata()
        assert "test" in loaded
        assert loaded["test"].version == "abc"
        assert loaded["test"].template_count == 10

    def test_get_scanner_options_no_adapter(self):
        mgr = TemplateManager()
        assert mgr.get_scanner_options("sslyze") == {}

    @patch.object(TemplateUpdater, "git_clone_or_pull", return_value=True)
    @patch.object(TemplateUpdater, "get_git_version", return_value="def5678")
    @patch.object(TemplateUpdater, "count_files", return_value=25)
    def test_update_templates(self, mock_count, mock_ver, mock_git, tmp_path):
        mgr = TemplateManager(
            base_dir=tmp_path,
            sources=[
                TemplateSource(
                    name="official",
                    scanner="nuclei",
                    source_type="git",
                    url="https://example.com/repo.git",
                ),
            ],
        )
        results = mgr.update_templates()
        assert len(results) == 1
        assert results[0].success
        assert results[0].new_version == "def5678"

        # Verify metadata was saved
        metadata = mgr.list_sources()
        assert len(metadata) == 1
        assert metadata[0].version == "def5678"

    def test_update_templates_disabled_source(self, tmp_path):
        mgr = TemplateManager(
            base_dir=tmp_path,
            sources=[
                TemplateSource(
                    name="disabled",
                    scanner="nuclei",
                    enabled=False,
                ),
            ],
        )
        results = mgr.update_templates()
        assert len(results) == 0


# ---------------------------------------------------------------------------
# TemplateUpdateReporter
# ---------------------------------------------------------------------------


class TestTemplateUpdateReporter:
    def test_format_cli_success(self):
        results = [
            UpdateResult(
                scanner="nuclei",
                source_name="official",
                success=True,
                new_version="abc",
                templates_added=50,
            ),
        ]
        text = TemplateUpdateReporter.format_cli(results)
        assert "OK" in text
        assert "50 templates" in text

    def test_format_cli_failure(self):
        results = [
            UpdateResult(
                scanner="nmap",
                source_name="test",
                success=False,
                error="network error",
            ),
        ]
        text = TemplateUpdateReporter.format_cli(results)
        assert "FAILED" in text
        assert "network error" in text

    def test_format_cli_empty(self):
        text = TemplateUpdateReporter.format_cli([])
        assert "No template sources" in text

    def test_format_summary(self):
        metadata = [
            TemplateMetadata(
                source_name="nuclei-official",
                scanner="nuclei",
                version="abc1234",
                template_count=100,
                last_updated="2026-01-01T00:00:00",
            ),
        ]
        text = TemplateUpdateReporter.format_summary(metadata)
        assert "nuclei-official" in text
        assert "abc1234" in text

    def test_format_summary_empty(self):
        text = TemplateUpdateReporter.format_summary([])
        assert "No template sources" in text


# ---------------------------------------------------------------------------
# TemplateUpdater
# ---------------------------------------------------------------------------


class TestTemplateUpdater:
    def test_count_files(self, tmp_path):
        (tmp_path / "a.yaml").write_text("test")
        (tmp_path / "b.yml").write_text("test")
        (tmp_path / "c.txt").write_text("test")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "d.yaml").write_text("test")

        count = TemplateUpdater.count_files(tmp_path, ["*.yaml", "*.yml"])
        assert count == 3

    def test_count_files_empty_dir(self, tmp_path):
        assert TemplateUpdater.count_files(tmp_path, ["*.yaml"]) == 0

    def test_count_files_nonexistent(self, tmp_path):
        assert (
            TemplateUpdater.count_files(
                tmp_path / "nope",
                ["*.yaml"],
            )
            == 0
        )
