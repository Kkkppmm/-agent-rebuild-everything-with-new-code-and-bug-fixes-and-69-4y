"""Tests for v6.21.0 security analyzers."""

from pathlib import Path

from devai import InsecureAllowedHostsAnalyzer, SecurityScanner


class TestInsecureAllowedHostsAnalyzer:
    def test_clean_explicit_hosts(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            'ALLOWED_HOSTS = ["example.com", "api.example.com"]\n',
            encoding="utf-8",
        )
        findings = InsecureAllowedHostsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_django_wildcard(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ALLOWED_HOSTS = ['*']\n",
            encoding="utf-8",
        )
        findings = InsecureAllowedHostsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "wildcard_allowed_hosts" for f in findings)
        assert any(f.severity == "high" for f in findings)
        assert any(f.setting == "ALLOWED_HOSTS" for f in findings)

    def test_detects_starlette_allowed_hosts(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            'allowed_hosts = ["*"]\n',
            encoding="utf-8",
        )
        findings = InsecureAllowedHostsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "wildcard_allowed_hosts" for f in findings)

    def test_detects_trusted_hosts(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            'TRUSTED_HOSTS = ("*",)\n',
            encoding="utf-8",
        )
        findings = InsecureAllowedHostsAnalyzer(str(tmp_path)).analyze()
        assert any(f.setting == "TRUSTED_HOSTS" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ALLOWED_HOSTS = ['*']\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_allowed_hosts",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_allowed_hosts" for cat in report.categories)
