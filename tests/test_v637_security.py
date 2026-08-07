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

    def test_detects_serve_public(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "SPECTACULAR_SETTINGS = {\n"
            "    'SERVE_PUBLIC': True,\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "serve_public_enabled" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_serve_include_schema(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SPECTACULAR_SETTINGS = {'SERVE_INCLUDE_SCHEMA': True}\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "serve_include_schema_enabled" for f in findings)

    def test_detects_spectacular_views_in_urls(self, tmp_path: Path):
        (tmp_path / "urls.py").write_text(
            "from drf_spectacular.views import SpectacularSwaggerView\n\n"
            "urlpatterns = [\n"
            "    path('api/schema/swagger/', SpectacularSwaggerView.as_view(), name='swagger'),\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "public_schema_view" for f in findings)

    def test_detects_swagger_url_pattern(self, tmp_path: Path):
        (tmp_path / "api_urls.py").write_text(
            "urlpatterns = [\n"
            "    path('openapi/', schema_view, name='openapi'),\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "swagger_url_pattern" for f in findings)

    def test_detects_public_schema_permissions(self, tmp_path: Path):
        (tmp_path / "urls.py").write_text(
            "from rest_framework.permissions import AllowAny\n"
            "from drf_spectacular.views import SpectacularAPIView\n\n"
            "urlpatterns = [\n"
            "    path('api/schema/', SpectacularAPIView.as_view(permission_classes=[AllowAny])),\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureApiDocsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "public_schema_permissions" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SPECTACULAR_SETTINGS = {'SERVE_PUBLIC': True}\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_api_docs_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_api_docs_settings" for cat in report.categories)
