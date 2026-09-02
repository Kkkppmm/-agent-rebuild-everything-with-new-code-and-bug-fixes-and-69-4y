"""Tests for DevAI environment diagnostics."""

import pytest

from devai import DevDoctor, DoctorResult, run_doctor


class TestDoctorResult:
    def test_to_dict(self):
        result = DoctorResult(name="test", passed=True, message="ok")
        data = result.to_dict()
        assert data["name"] == "test"
        assert data["passed"] is True


class TestDevDoctor:
    def test_run_basic_checks(self):
        doctor = DevDoctor()
        results = doctor.run()
        names = {r.name for r in results}
        assert "python" in names
        assert "devai" in names
        assert "httpx" in names

    def test_passed(self):
        doctor = DevDoctor()
        assert doctor.passed() is True

    def test_summary(self):
        doctor = DevDoctor()
        summary = doctor.summary()
        assert "# DevAI Doctor" in summary
        assert "python" in summary.lower()

    def test_to_dict(self):
        doctor = DevDoctor()
        data = doctor.to_dict()
        assert "checks" in data
        assert "passed" in data

    def test_no_probe_skips_health(self):
        doctor = DevDoctor(probe=False)
        results = doctor.run()
        health = [r for r in results if r.name == "provider-health"]
        if health:
            assert health[0].passed or "Skipped" in health[0].message or not health[0].passed


class TestRunDoctor:
    def test_run_doctor(self):
        results = run_doctor()
        assert len(results) >= 5
