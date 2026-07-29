"""Tests for environment diagnostics."""

from devai.doctor import DevDoctor, run_doctor


class TestDevDoctor:
    def test_run_doctor(self):
        result = run_doctor()
        assert result.checks
        assert any(c.name == "python" for c in result.checks)
        assert any(c.name == "devai" for c in result.checks)

    def test_format_report(self):
        result = DevDoctor().run()
        report = result.format_report()
        assert "DevAI Doctor" in report
        assert "Overall:" in report

    def test_python_version_ok(self):
        result = run_doctor()
        python_check = next(c for c in result.checks if c.name == "python")
        assert python_check.status == "ok"
