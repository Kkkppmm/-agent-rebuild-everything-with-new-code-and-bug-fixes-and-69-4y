"""Tests for OpenAPIAnalyzer."""

from pathlib import Path

from devai.openapi_analyzer import OpenAPIAnalyzer


INSECURE_SPEC = """\
openapi: 3.0.3
info:
  title: Demo API
  version: 1.0.0
servers:
  - url: http://api.example.com
    description: Production
security: []
paths:
  /admin/users:
    get:
      summary: List users
  /debug/health:
    get:
      summary: Debug health
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: query
      name: api_key
    BasicAuth:
      type: http
      scheme: basic
    OAuth2:
      type: oauth2
      flows:
        implicit:
          authorizationUrl: http://auth.example.com/oauth
          scopes: {}
"""

HARDENED_SPEC = """\
openapi: 3.0.3
info:
  title: Demo API
  version: 1.0.0
servers:
  - url: https://api.example.com
security:
  - BearerAuth: []
paths:
  /users:
    get:
      summary: List users
      security:
        - BearerAuth: []
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
"""


class TestOpenAPIAnalyzer:
    def test_detects_insecure_spec(self, tmp_path: Path):
        (tmp_path / "openapi.yaml").write_text(INSECURE_SPEC, encoding="utf-8")
        analyzer = OpenAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http_server" in kinds
        assert "empty_global_security" in kinds
        assert "api_key_in_query" in kinds
        assert "oauth_implicit_flow" in kinds
        assert "sensitive_path" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_spec_clean(self, tmp_path: Path):
        (tmp_path / "openapi.yaml").write_text(HARDENED_SPEC, encoding="utf-8")
        analyzer = OpenAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert len(analyzer.infos) == 1
        assert analyzer.infos[0].title == "Demo API"

    def test_no_specs_returns_full_score(self, tmp_path: Path):
        analyzer = OpenAPIAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_json_spec(self, tmp_path: Path):
        (tmp_path / "openapi.json").write_text(
            '{"openapi":"3.0.0","info":{"title":"X","version":"1.0.0"},'
            '"servers":[{"url":"http://evil.com"}]}',
            encoding="utf-8",
        )
        analyzer = OpenAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "insecure_http_server" for f in findings)

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "openapi.yaml").write_text(INSECURE_SPEC, encoding="utf-8")
        analyzer = OpenAPIAnalyzer(str(tmp_path))
        ctx = analyzer.to_context()
        assert "OpenAPI analysis" in ctx
        assert "insecure_http_server" in ctx or "[medium]" in ctx

    def test_generate_hardened_snippet(self):
        snippet = OpenAPIAnalyzer(".").generate_hardened_snippet()
        assert "HTTPS" in snippet
