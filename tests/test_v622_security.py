"""Tests for v6.22.0 security analyzers."""

from pathlib import Path

from devai import SecurityScanner, WeakSecretKeyAnalyzer


class TestWeakSecretKeyAnalyzer:
    def test_clean_env_lookup(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "import os\nSECRET_KEY = os.environ.get('SECRET_KEY')\n",
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_django_insecure_prefix(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECRET_KEY = 'django-insecure-abc123'\n",
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_secret_literal" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_changeme_literal(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "secret_key = 'changeme'\n",
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_secret_literal" for f in findings)

    def test_detects_short_secret(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "APP_SECRET = 'shortkey'\n",
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "short_secret_key" for f in findings)

    def test_detects_hardcoded_long_secret(self, tmp_path: Path):
        long_key = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghij"
        (tmp_path / "settings.py").write_text(
            f"SECRET_KEY = '{long_key}'\n",
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_secret_key" for f in findings)

    def test_detects_weak_env_default(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "import os\nSECRET_KEY = os.environ.get('SECRET_KEY', 'changeme')\n",
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern.startswith("weak_env_default") for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECRET_KEY = 'changeme'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("weak_secret_key",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "weak_secret_key" for cat in report.categories)
