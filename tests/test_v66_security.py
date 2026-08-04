"""Tests for DevAI v6.6.0 security analyzers."""

from pathlib import Path

from devai import (
    InsecureFileUploadAnalyzer,
    SecurityScanner,
    WeakPasswordAnalyzer,
    __version__,
)


class TestV66Security:
    def test_version(self):
        assert __version__ == "6.6.0"

    def test_security_scan_includes_new_checks(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def ok(): return 1\n", encoding="utf-8")
        report = SecurityScanner(str(tmp_path)).scan()
        names = {cat.name for cat in report.categories}
        assert "insecure_file_upload" in names
        assert "weak_password" in names
        assert len(report.categories) == 34

    def test_insecure_file_upload_in_security_scan(self, tmp_path: Path):
        (tmp_path / "upload.py").write_text(
            'def upload(f):\n    f.save(f.filename)\n',
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_file_upload",)).scan()
        assert report.total_findings >= 1
        assert report.recommendations

    def test_weak_password_in_security_scan(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def register(user, password):\n    user.password = password\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("weak_password",)).scan()
        assert report.total_findings >= 1
        assert report.recommendations

    def test_analyzers_exported(self):
        assert InsecureFileUploadAnalyzer is not None
        assert WeakPasswordAnalyzer is not None
