"""Tests for v6.15.0 security analyzers."""

from pathlib import Path

from devai import SecurityScanner, WildcardHostsAnalyzer


class TestWildcardHostsAnalyzer:
    def test_clean_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ALLOWED_HOSTS = ['example.com', 'api.example.com']\n",
            encoding="utf-8",
        )
        findings = WildcardHostsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_wildcard_allowed_hosts_list(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ALLOWED_HOSTS = ['*']\n",
            encoding="utf-8",
        )
        findings = WildcardHostsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "wildcard_host_setting" for f in findings)
        assert any(f.setting == "ALLOWED_HOSTS" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_wildcard_allowed_hosts_string(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            'ALLOWED_HOSTS = "*"\n',
            encoding="utf-8",
        )
        findings = WildcardHostsAnalyzer(str(tmp_path)).analyze()
        assert len(findings) == 1

    def test_detects_trusted_origins_wildcard(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CSRF_TRUSTED_ORIGINS = ['https://app.example.com', '*']\n",
            encoding="utf-8",
        )
        findings = WildcardHostsAnalyzer(str(tmp_path)).analyze()
        assert any(f.setting == "CSRF_TRUSTED_ORIGINS" for f in findings)

    def test_detects_os_environ_setdefault(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import os\n"
            "os.environ.setdefault('ALLOWED_HOSTS', '*')\n",
            encoding="utf-8",
        )
        findings = WildcardHostsAnalyzer(str(tmp_path)).analyze()
        assert any(f.setting == "ALLOWED_HOSTS" for f in findings)


class TestWildcardHostsScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ALLOWED_HOSTS = ['*']\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("wildcard_hosts",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "wildcard_hosts" for cat in report.categories)
