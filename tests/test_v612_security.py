"""Tests for v6.12.0 security analyzers."""

from pathlib import Path

from devai import AssertSecurityAnalyzer, SecurityScanner


class TestAssertSecurityAnalyzer:
    def test_clean_code_no_asserts(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def add(a, b):\n    return a + b\n",
            encoding="utf-8",
        )
        findings = AssertSecurityAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_security_assert(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def view(request):\n"
            "    assert request.user.is_authenticated\n"
            "    return 'ok'\n",
            encoding="utf-8",
        )
        findings = AssertSecurityAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "security_assert" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_permission_assert(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            "def delete_user(user, target):\n"
            "    assert user.has_permission('admin')\n"
            "    target.delete()\n",
            encoding="utf-8",
        )
        findings = AssertSecurityAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "security_assert" for f in findings)

    def test_allows_isinstance_assert(self, tmp_path: Path):
        (tmp_path / "validate.py").write_text(
            "def process(value):\n"
            "    assert isinstance(value, str)\n"
            "    return value.upper()\n",
            encoding="utf-8",
        )
        findings = AssertSecurityAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "security_assert" for f in findings)

    def test_skips_test_files(self, tmp_path: Path):
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_auth.py").write_text(
            "def test_auth():\n"
            "    assert user.is_authenticated\n",
            encoding="utf-8",
        )
        findings = AssertSecurityAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_production_assert_low_severity(self, tmp_path: Path):
        (tmp_path / "logic.py").write_text(
            "def compute(x):\n"
            "    assert x > 0\n"
            "    return x * 2\n",
            encoding="utf-8",
        )
        findings = AssertSecurityAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "production_assert" and f.severity == "low" for f in findings)


class TestAssertSecurityScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "def handler(request):\n"
            "    assert request.user.is_admin\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("assert_security",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "assert_security" for cat in report.categories)
