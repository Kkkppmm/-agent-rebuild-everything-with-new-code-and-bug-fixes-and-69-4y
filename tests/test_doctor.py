"""Tests for DevDoctor environment diagnostics."""

import json
from pathlib import Path

from devai import DevDoctor, run_doctor
from devai.config_file import config_file_template


class TestDevDoctor:
    def test_run_passes_in_clean_env(self):
        result = run_doctor()
        assert result.passed is True
        assert any(check.name == "python" for check in result.checks)
        assert any(check.name == "devai" for check in result.checks)

    def test_summary_output(self):
        result = run_doctor()
        summary = result.summary()
        assert "DevAI Doctor" in summary
        assert "PASS" in summary

    def test_to_dict(self):
        result = run_doctor()
        data = result.to_dict()
        assert "passed" in data
        assert len(data["checks"]) >= 4

    def test_with_config_file(self, tmp_path: Path):
        config_path = tmp_path / ".devai.yaml"
        config_path.write_text(
            config_file_template(provider="mock", model="mock-model"),
            encoding="utf-8",
        )
        result = DevDoctor(tmp_path).run()
        config_check = next(c for c in result.checks if c.name == "config")
        assert config_check.passed is True
        assert ".devai.yaml" in config_check.message

    def test_provider_check_mock(self):
        result = run_doctor(check_provider=True)
        provider_check = next((c for c in result.checks if c.name == "provider"), None)
        assert provider_check is not None
        assert provider_check.passed is True

    def test_cli_doctor_json(self, capsys):
        from devai.cli import main

        main(["doctor", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["passed"] is True
