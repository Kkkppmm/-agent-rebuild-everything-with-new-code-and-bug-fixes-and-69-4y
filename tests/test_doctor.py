"""Tests for DevAI environment diagnostics."""

import json
import os

from devai.doctor import DevDoctor, DoctorCheck, DoctorResult, run_doctor


class TestDevDoctor:
    def test_run_all_checks(self):
        doctor = DevDoctor()
        result = doctor.run()
        assert isinstance(result, DoctorResult)
        assert len(result.checks) >= 6
        names = {check.name for check in result.checks}
        assert "python" in names
        assert "devai" in names
        assert "git" in names

    def test_python_version_check(self):
        doctor = DevDoctor()
        check = doctor._check_python_version()
        assert check.passed is True
        assert "Python" in check.message

    def test_api_keys_check_with_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        doctor = DevDoctor()
        check = doctor._check_api_keys()
        assert check.passed is True

    def test_api_keys_check_without_env(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("DEVAI_API_KEY", raising=False)
        doctor = DevDoctor()
        check = doctor._check_api_keys()
        assert check.passed is True
        assert "No API keys" in check.message

    def test_check_provider(self):
        doctor = DevDoctor()
        result = doctor.run(check_provider=True)
        provider_checks = [c for c in result.checks if c.name == "provider"]
        assert len(provider_checks) == 1
        assert provider_checks[0].passed is True

    def test_summary_markdown(self):
        result = DoctorResult(
            checks=[
                DoctorCheck(name="python", passed=True, message="ok"),
                DoctorCheck(name="api_keys", passed=False, message="missing"),
            ]
        )
        summary = result.summary()
        assert "DevAI Doctor" in summary
        assert "FAIL" in summary
        assert "api_keys" in summary

    def test_to_dict(self):
        result = DoctorResult(
            checks=[DoctorCheck(name="devai", passed=True, message="installed")]
        )
        data = result.to_dict()
        assert data["healthy"] is True
        assert len(data["checks"]) == 1


class TestRunDoctor:
    def test_run_doctor_convenience(self):
        result = run_doctor()
        assert isinstance(result, DoctorResult)

    def test_json_serializable(self):
        result = run_doctor()
        json.dumps(result.to_dict())
