"""Tests for v6.22.0 security analyzers."""

from pathlib import Path

from devai import SecurityScanner, WeakSecretKeyAnalyzer


class TestWeakSecretKeyAnalyzer:
    def test_clean_env_based_secret(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            'SECRET_KEY = os.environ["SECRET_KEY"]\n',
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_django_insecure_prefix(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            'SECRET_KEY = "django-insecure-abc123xyz"\n',
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_secret_key_value" for f in findings)
        assert any(f.severity == "high" for f in findings)
        assert any(f.setting == "SECRET_KEY" for f in findings)

    def test_detects_short_secret_key(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            'secret_key = "short"\n',
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "short_secret_key" for f in findings)

    def test_detects_changeme_placeholder(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            'APP_SECRET_KEY = "changeme"\n',
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_secret_key_value" for f in findings)

    def test_accepts_strong_secret_key(self, tmp_path: Path):
        strong = "x" * 48 + "Ab3!zQ9$mN2@pL7#vR4&wT6*uY8^cE0"
        (tmp_path / "settings.py").write_text(
            f'SECRET_KEY = "{strong}"\n',
            encoding="utf-8",
        )
        findings = WeakSecretKeyAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            'SECRET_KEY = "django-insecure-test"\n',
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("weak_secret_key",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "weak_secret_key" for cat in report.categories)
