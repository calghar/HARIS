"""Tests for scanner_config.py validation logic."""

import pytest

from haris.data.scanner_config import _validate_nuclei_config


class TestNucleiConfigValidation:
    def test_valid_config_passes(self) -> None:
        """Valid config dict validates without warnings."""
        valid = {
            "severity_map": {"critical": "CRITICAL", "high": "HIGH"},
            "confidence_map": {"critical": "CONFIRMED"},
            "baseline_template_dirs": ["http/exposures", "dast"],
            "max_selected_tags": 10,
            "deny_tags": ["dos"],
            "min_tag_templates": 3,
            "max_tag_templates": 300,
            "tag_map": {"sql": ["sql_injection"]},
            "tech_tag_map": {"wordpress": ["wordpress"]},
            "tech_workflow_map": {"wordpress": "workflows/wordpress-workflow.yaml"},
            "remediation_map": {"sql_injection": "Use parameterised queries"},
        }
        result = _validate_nuclei_config(valid)
        assert result == valid

    def test_wrong_type_warns_and_returns_data(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Wrong type logs warning but returns data unchanged."""
        invalid = {
            "severity_map": "not-a-dict",  # should be dict
            "deny_tags": "not-a-list",  # should be list
        }
        result = _validate_nuclei_config(invalid)
        assert result == invalid
        assert "nuclei.yaml failed schema validation" in caplog.text

    def test_empty_config_validates(self) -> None:
        """Empty dict validates successfully (all fields have defaults)."""
        result = _validate_nuclei_config({})
        assert result == {}

    def test_real_nuclei_yaml_validates(self) -> None:
        """The actual nuclei.yaml file validates successfully."""
        # Clear cache to force reload with validation
        from haris.data.scanner_config import (
            _load_scanner_config,
            _scanner_config_cache,
        )

        _scanner_config_cache.pop("nuclei", None)

        data = _load_scanner_config("nuclei")
        assert isinstance(data, dict)
        assert "severity_map" in data
        assert "tech_workflow_map" in data

    def test_baseline_template_dirs_are_strings(self) -> None:
        """baseline_template_dirs validates as list of strings."""
        valid = {"baseline_template_dirs": ["http/exposures", "dast"]}
        result = _validate_nuclei_config(valid)
        assert result == valid

        # Integer list should fail validation but still return data
        invalid = {"baseline_template_dirs": [123, 456]}
        result = _validate_nuclei_config(invalid)
        assert result == invalid
