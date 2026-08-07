"""Tests for v6.40.0 security analyzers."""

from pathlib import Path

from devai import InsecureGraphqlSettingsAnalyzer, SecurityScanner


class TestInsecureGraphqlSettingsAnalyzer:
    def test_clean_graphql_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "INTROSPECTION_ENABLED = False\n"
            "GRAPHIQL_ENABLED = False\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_introspection_enabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "INTROSPECTION_ENABLED = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "introspection_enabled" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_graphiql_enabled(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "GRAPHIQL_ENABLED = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "graphiql_enabled" for f in findings)

    def test_detects_playground_enabled(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "GRAPHQL_PLAYGROUND = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "graphiql_enabled" for f in findings)

    def test_detects_empty_graphene_middleware(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "GRAPHENE = {\n"
            "    'SCHEMA': 'api.schema.schema',\n"
            "    'MIDDLEWARE': [],\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "empty_graphql_middleware" for f in findings)

    def test_detects_public_graphql_view(self, tmp_path: Path):
        (tmp_path / "urls.py").write_text(
            "path('graphql', GraphQLView.as_view(permission_classes=[AllowAny]))\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "public_graphql_view" for f in findings)

    def test_detects_graphiql_on_route(self, tmp_path: Path):
        (tmp_path / "router.py").write_text(
            "app.add_route('/graphql', GraphQLRouter(schema, graphiql=True))\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "graphiql_enabled" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "INTROSPECTION_ENABLED = True\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_graphql_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_graphql_settings" for cat in report.categories)
