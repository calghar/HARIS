from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class TestImageScanFixes:
    def test_runtime_stage_upgrades_zlib_and_removes_base_pip(self) -> None:
        parts = (ROOT / "Dockerfile").read_text().split("FROM python:3.13-slim@")
        assert len(parts) == 3
        runtime = parts[2]
        assert "zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1" in runtime
        assert "/usr/local/lib/python3.13/site-packages/pip" in runtime

    def test_trivy_ignore_is_limited_to_nuclei_and_anthropic_placeholders(self) -> None:
        ignore = yaml.safe_load((ROOT / ".trivyignore.yaml").read_text())
        assert ignore["vulnerabilities"]
        for entry in ignore["vulnerabilities"]:
            assert entry["paths"] == ["usr/local/bin/nuclei"], entry["id"]
            assert entry["expired_at"], entry["id"]
        assert [(s["id"], s["paths"]) for s in ignore["secrets"]] == [
            ("gcp-service-account", ["**/site-packages/anthropic/**"])
        ]
        workflow = (ROOT / ".github/workflows/security.yml").read_text()
        assert "trivyignores: .trivyignore.yaml" in workflow
        assert "severity: HIGH,CRITICAL" in workflow
        assert "codeql-action/analyze" not in workflow
