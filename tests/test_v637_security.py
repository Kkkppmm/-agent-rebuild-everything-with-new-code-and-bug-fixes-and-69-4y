"""Tests for v6.37.0 security analyzers."""

from pathlib import Path

from devai import InsecureApiDocsSettingsAnalyzer, SecurityScanner


class TestInsecureApiDocsSettingsAnalyzer:
    def test_clean_api_docs_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SPECTACULAR_SETTINGS = {\n"
            "    'SERVE_PUBLIC': False,\n"
            "    'SERVE_INCLUDE_SCHEMA': False,\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_spectacular_public_schema(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "SPECTACULAR_SETTINGS = {\n"
            "    'SERVE_PUBLIC': True,\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "spectacular_public_schema" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_spectacular_include_schema(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SPECTACULAR_SETTINGS = {'SERVE_INCLUDE_SCHEMA': True}\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "spectacular_include_schema" for f in findings)

    def test_detects_public_schema_view(self, tmp_path: Path):
        (tmp_path / "urls.py").write_text(
            "from drf_yasg.views import get_schema_view\n\n"
            "schema_view = get_schema_view(public=True)\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "public_schema_view" for f in findings)

    def test_detects_swagger_url_exposed(self, tmp_path: Path):
        (tmp_path / "urls.py").write_text(
            "from django.urls import path\n"
            "from drf_spectacular.views import SpectacularSwaggerView\n\n"
            "urlpatterns = [\n"
            "    path('swagger/', SpectacularSwaggerView.as_view()),\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "swagger_url_exposed" for f in findings)

    def test_detects_swagger_no_session_auth(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "SWAGGER_SETTINGS = {'USE_SESSION_AUTH': False}\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "swagger_no_session_auth" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SPECTACULAR_SETTINGS = {'SERVE_PUBLIC': True}\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_api_docs_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_api_docs_settings" for cat in report.categories)
