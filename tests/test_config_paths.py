from haris.config.loader import default_config_path
from haris.config.paths import packaged_config_dir, resolve_config_file


def test_packaged_config_contains_default_and_scanner_yaml():
    root = packaged_config_dir()
    assert (root / "default_config.yaml").is_file()
    assert (root / "scanners" / "nuclei.yaml").is_file()


def test_cwd_config_overrides_packaged(tmp_path, monkeypatch):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "default_config.yaml").write_text("profile: quick\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HARIS_CONFIG", raising=False)
    assert resolve_config_file("default_config.yaml").read_text() == "profile: quick\n"
    assert resolve_config_file("scanner_data.yaml").parent == packaged_config_dir()


def test_env_var_beats_cwd_and_packaged(tmp_path, monkeypatch):
    custom = tmp_path / "custom.yaml"
    custom.write_text("profile: quick\n")
    monkeypatch.setenv("HARIS_CONFIG", str(custom))
    assert default_config_path() == custom
