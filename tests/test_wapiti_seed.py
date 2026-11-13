import pytest

from haris.models.target import Target
from haris.scanners.wapiti_scanner import WapitiScanner
from haris.scanners.wapiti_seed import wapiti_seed_urls

BASE = "http://127.0.0.1:14280"
SESSION_DIR = "/tmp/wapiti-session"


class TestWapitiSeedUrls:
    def test_paths_become_absolute_urls_in_order(self) -> None:
        assert wapiti_seed_urls(BASE, ["/a", "/b/c"]) == [f"{BASE}/a", f"{BASE}/b/c"]

    def test_query_string_is_kept(self) -> None:
        assert wapiti_seed_urls(BASE, ["/x/y?f=a&g=1"]) == [f"{BASE}/x/y?f=a&g=1"]

    def test_base_path_is_dropped_and_port_kept(self) -> None:
        urls = wapiti_seed_urls("https://app.example.com:8443/WebGoat", ["/WebGoat/x"])
        assert urls == ["https://app.example.com:8443/WebGoat/x"]

    def test_empty_list_gives_no_urls(self) -> None:
        assert wapiti_seed_urls(BASE, []) == []

    @pytest.mark.parametrize("value", ["/a", None, ("/a",), {"/a"}])
    def test_non_list_is_rejected(self, value: object) -> None:
        with pytest.raises(ValueError, match="list"):
            wapiti_seed_urls(BASE, value)

    @pytest.mark.parametrize(
        "entry", ["a/b", "", "http://evil.test/", "//evil.test/x", "/a b", 7, None]
    )
    def test_bad_entry_is_rejected(self, entry: object) -> None:
        with pytest.raises(ValueError, match="start with '/'"):
            wapiti_seed_urls(BASE, ["/ok", entry])


class TestWapitiSeedArgv:
    def test_seed_paths_become_start_pairs_on_the_target_origin(self) -> None:
        scanner = WapitiScanner({"seed_paths": ["/WebGoat/a", "/WebGoat/b?p=1"]})
        cmd = scanner._build_command(
            Target(base_url=f"{BASE}/WebGoat"), "/tmp/o", SESSION_DIR
        )
        starts = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--start"]
        assert starts == [f"{BASE}/WebGoat/a", f"{BASE}/WebGoat/b?p=1"]

    def test_default_adds_no_start_flag(self) -> None:
        cmd = WapitiScanner()._build_command(
            Target(base_url=BASE), "/tmp/o", SESSION_DIR
        )
        assert "--start" not in cmd

    def test_bad_seed_path_raises_when_building(self) -> None:
        scanner = WapitiScanner({"seed_paths": ["//evil.test/x"]})
        with pytest.raises(ValueError, match="start with '/'"):
            scanner._build_command(Target(base_url=BASE), "/tmp/o", SESSION_DIR)
