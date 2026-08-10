"""Tests for v6.33.0 security analyzers."""

from pathlib import Path

from devai import InsecureRestFrameworkSettingsAnalyzer, SecurityScanner


class TestInsecureRestFrameworkSettingsAnalyzer:
    def test_clean_rest_framework_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "REST_FRAMEWORK = {\n"
            "    'DEFAULT_PERMISSION_CLASSES': [\n"
            "        'rest_framework.permissions.IsAuthenticated',\n"
            "    ],\n"
            "    'DEFAULT_AUTHENTICATION_CLASSES': [\n"
            "        'rest_framework.authentication.SessionAuthentication',\n"
            "    ],\n"
            "    'DEFAULT_RENDERER_CLASSES': [\n"
            "        'rest_framework.renderers.JSONRenderer',\n"
            "    ],\n"
            "    'DEFAULT_THROTTLE_CLASSES': [\n"
            "        'rest_framework.throttling.AnonRateThrottle',\n"
            "    ],\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureRestFrameworkSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_allow_any_default(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "REST_FRAMEWORK = {\n"
            "    'DEFAULT_PERMISSION_CLASSES': [\n"
            "        'rest_framework.permissions.AllowAny',\n"
            "    ],\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureRestFrameworkSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "allow_any_default" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_no_authentication_classes(self, tmp_path: Path):
        (tmp_path / "prod.py").write_text(
            "REST_FRAMEWORK = {\n"
            "    'DEFAULT_AUTHENTICATION_CLASSES': [],\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureRestFrameworkSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "no_authentication_classes" for f in findings)

    def test_detects_browsable_api_in_production(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "REST_FRAMEWORK = {\n"
            "    'DEFAULT_RENDERER_CLASSES': [\n"
            "        'rest_framework.renderers.JSONRenderer',\n"
            "        'rest_framework.renderers.BrowsableAPIRenderer',\n"
            "    ],\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureRestFrameworkSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "browsable_api_in_production" for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_detects_missing_throttle_classes(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "REST_FRAMEWORK = {\n"
            "    'DEFAULT_THROTTLE_CLASSES': [],\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureRestFrameworkSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_throttle_classes" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "REST_FRAMEWORK = {\n"
            "    'DEFAULT_PERMISSION_CLASSES': [\n"
            "        'rest_framework.permissions.AllowAny',\n"
            "    ],\n"
            "}\n",
            encoding="utf-8",
        )
        report = SecurityScanner(
            str(tmp_path), checks=("insecure_rest_framework_settings",)
        ).scan()
        assert report.total_findings >= 1
        assert any(
            cat.name == "insecure_rest_framework_settings" for cat in report.categories
        )
