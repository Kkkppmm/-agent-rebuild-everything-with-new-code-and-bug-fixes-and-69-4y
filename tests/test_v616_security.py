"""Tests for v6.16.0 security analyzers."""

from pathlib import Path

from devai import InsecureSecretKeyAnalyzer, SecurityScanner


class TestInsecureSecretKeyAnalyzer:
    def test_clean_secret_key(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECRET_KEY = 'abcdefghijklmnopqrstuvwxyz0123456789'\n",
            encoding="utf-8",
        )
        findings = InsecureSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_changeme_secret(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            'SECRET_KEY = "changeme"\n',
            encoding="utf-8",
        )
        findings = InsecureSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_secret_value" for f in findings)
        assert any(f.setting == "SECRET_KEY" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_django_insecure_prefix(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            'SECRET_KEY = "django-insecure-abc123"\n',
            encoding="utf-8",
        )
        findings = InsecureSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_secret_value" for f in findings)

    def test_detects_short_secret_key(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            'APP_SECRET_KEY = "shortkey123"\n',
            encoding="utf-8",
        )
        findings = InsecureSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "short_secret_key" for f in findings)
        assert any(f.setting == "APP_SECRET_KEY" for f in findings)

    def test_detects_os_environ_setdefault(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import os\n"
            "os.environ.setdefault('SECRET_KEY', 'dev')\n",
            encoding="utf-8",
        )
        findings = InsecureSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.setting == "SECRET_KEY" for f in findings)


class TestInsecureSecretKeyScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            'SECRET_KEY = "changeme"\n',
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_secret_key",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_secret_key" for cat in report.categories)
