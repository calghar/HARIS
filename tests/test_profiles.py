import pytest

from src.core.profiles import PROFILES, get_profile, list_profiles


class TestProfiles:
    def test_all_profiles_have_required_fields(self):
        for name, profile in PROFILES.items():
            assert profile.name == name
            assert profile.display_name
            assert profile.description
            assert profile.scanners
            assert profile.estimated_duration
            assert profile.use_case

    def test_get_profile_known(self):
        profile = get_profile("quick")
        assert profile.name == "quick"

    def test_get_profile_unknown_raises(self):
        with pytest.raises(KeyError, match="Unknown profile"):
            get_profile("nonexistent")

    def test_list_profiles(self):
        profiles = list_profiles()
        assert len(profiles) >= 4
        names = [p.name for p in profiles]
        assert "quick" in names
        assert "full" in names
        assert "pre-launch" in names

    def test_quick_profile_has_no_external_tools(self):
        profile = get_profile("quick")
        external = {"wapiti", "sslyze", "nmap", "nikto", "nuclei"}
        assert not external.intersection(profile.scanner_set())

    def test_full_profile_includes_external_tools(self):
        profile = get_profile("full")
        assert "wapiti" in profile.scanner_set()
        assert "nmap" in profile.scanner_set()
