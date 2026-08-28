"""Tests for v6.32.0 security analyzers."""

from pathlib import Path

from devai import InsecureMiddlewareSettingsAnalyzer, SecurityScanner


class TestInsecureMiddlewareSettingsAnalyzer:
    def test_clean_middleware_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "MIDDLEWARE = [\n"
            "    'django.middleware.security.SecurityMiddleware',\n"
            "    'django.middleware.csrf.CsrfViewMiddleware',\n"
            "    'django.middleware.clickjacking.XFrameOptionsMiddleware',\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureMiddlewareSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_missing_security_middleware(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "MIDDLEWARE = [\n"
            "    'django.middleware.csrf.CsrfViewMiddleware',\n"
            "    'django.middleware.clickjacking.XFrameOptionsMiddleware',\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureMiddlewareSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_security_middleware" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_missing_csrf_middleware(self, tmp_path: Path):
        (tmp_path / "prod.py").write_text(
            "MIDDLEWARE = [\n"
            "    'django.middleware.security.SecurityMiddleware',\n"
            "    'django.middleware.clickjacking.XFrameOptionsMiddleware',\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureMiddlewareSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_csrf_middleware" for f in findings)

    def test_detects_debug_toolbar_in_production(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "MIDDLEWARE = [\n"
            "    'debug_toolbar.middleware.DebugToolbarMiddleware',\n"
            "    'django.middleware.security.SecurityMiddleware',\n"
            "    'django.middleware.csrf.CsrfViewMiddleware',\n"
            "    'django.middleware.clickjacking.XFrameOptionsMiddleware',\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureMiddlewareSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "debug_toolbar_in_production" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_cors_before_security_middleware(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "MIDDLEWARE = [\n"
            "    'corsheaders.middleware.CorsMiddleware',\n"
            "    'django.middleware.security.SecurityMiddleware',\n"
            "    'django.middleware.csrf.CsrfViewMiddleware',\n"
            "    'django.middleware.clickjacking.XFrameOptionsMiddleware',\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureMiddlewareSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "cors_before_security_middleware" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "MIDDLEWARE = []\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_middleware_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_middleware_settings" for cat in report.categories)
