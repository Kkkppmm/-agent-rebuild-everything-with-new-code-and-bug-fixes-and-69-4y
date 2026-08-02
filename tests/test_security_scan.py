"""Tests for DevAI SecurityScanner."""

from pathlib import Path

import pytest

from devai import SecurityScanner, SecurityScanCategory, SecurityScanReport


class TestSecurityScanner:
    def test_clean_project(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

        scanner = SecurityScanner(str(tmp_path))
        report = scanner.scan()
        assert report.overall_score == 100.0
        assert report.total_findings == 0
        assert len(report.categories) == 14

    def test_detects_secrets(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            'API_KEY = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"\n',
            encoding="utf-8",
        )
        scanner = SecurityScanner(str(tmp_path), checks=("secrets",))
        report = scanner.scan()
        assert report.total_findings >= 1
        assert report.overall_score < 100.0

    def test_detects_dangerous_calls(self, tmp_path: Path):
        (tmp_path / "risky.py").write_text("eval(user_input)\n", encoding="utf-8")
        scanner = SecurityScanner(str(tmp_path), checks=("dangerous_calls",))
        report = scanner.scan()
        assert report.total_findings >= 1
        assert any(cat.name == "dangerous_calls" for cat in report.categories)

    def test_unknown_check_raises(self):
        with pytest.raises(ValueError, match="Unknown security checks"):
            SecurityScanner(".", checks=("not_a_check",))

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def foo(): return 1\n", encoding="utf-8")
        scanner = SecurityScanner(str(tmp_path))
        assert "Security scan:" in scanner.summary()
        assert "Security scan results:" in scanner.to_context()

    def test_report_exports(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def foo(): return 1\n", encoding="utf-8")
        report = SecurityScanner(str(tmp_path)).scan()
        assert report.to_dict()["overall_score"] == 100.0
        assert "# Security Scan Report" in report.to_markdown()
        assert '"overall_score"' in report.to_json()

    def test_recommendations_on_findings(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text("eval(x)\n", encoding="utf-8")
        report = SecurityScanner(str(tmp_path), checks=("dangerous_calls",)).scan()
        assert report.recommendations

    def test_health_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def foo(): return 1\n", encoding="utf-8")
        assert SecurityScanner(str(tmp_path)).health_score() == 100.0

    def test_category_dataclass(self):
        cat = SecurityScanCategory(name="secrets", score=80.0, findings=2, summary="2 findings")
        assert cat.name == "secrets"

    def test_report_summary_includes_recommendations(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text("eval(x)\n", encoding="utf-8")
        report = SecurityScanner(str(tmp_path), checks=("dangerous_calls",)).scan()
        text = report.summary()
        assert "Recommendations:" in text
