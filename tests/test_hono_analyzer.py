"""Tests for HonoAnalyzer."""

from pathlib import Path

from devai.hono_analyzer import HonoAnalyzer, HonoFinding


INSECURE_HONO_APP = """\
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { basicAuth } from 'hono/basic-auth';
import { bearerAuth } from 'hono/bearer-auth';
import { jwt } from 'hono/jwt';

const app = new Hono();

app.use('*', cors({ origin: '*' }));
app.use('/api/*', basicAuth({ username: 'admin', password: 'super_secret_password' }));
app.use('/internal/*', bearerAuth({ token: 'hardcoded_bearer_token_abc123' }));
app.use('/auth/*', jwt({ secret: 'jwt_secret_hardcoded_value' }));

app.get('/admin/users', (c) => c.json({ users: [] }));
app.get('/debug/env', (c) => c.json({ env: process.env }));

app.post('/proxy', async (c) => {
  const res = await fetch('http://10.0.0.1:8080/internal');
  return c.json(await res.json());
});

export default app;
"""

HARDENED_HONO_APP = """\
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import { bearerAuth } from 'hono/bearer-auth';

const app = new Hono();

app.use('*', secureHeaders());
app.use(
  '/api/*',
  cors({ origin: process.env.ALLOWED_ORIGIN ?? 'https://example.com' }),
);
app.use('/admin/*', bearerAuth({ token: process.env.ADMIN_TOKEN ?? '' }));

app.get('/health', (c) => c.json({ status: 'ok' }));

export default app;
"""

INSECURE_WRANGLER = """\
name = "my-hono-app"
main = "src/index.ts"
compatibility_date = "2024-01-01"
compatibility_flags = ["nodejs_compat"]

[vars]
API_KEY = "hardcoded_api_key_value_12345"
SECRET_TOKEN = "super_secret_wrangler_token"

[dev]
hostname = "0.0.0.0"
"""


class TestHonoAnalyzer:
    def test_detects_insecure_hono_app(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.ts").write_text(INSECURE_HONO_APP, encoding="utf-8")
        analyzer = HonoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "cors_wildcard" in kinds
        assert "basic_auth_hardcoded" in kinds
        assert "bearer_auth_hardcoded" in kinds
        assert "jwt_secret_hardcoded" in kinds
        assert "unprotected_admin_route" in kinds
        assert "proxy_internal" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_wrangler(self, tmp_path: Path):
        (tmp_path / "wrangler.toml").write_text(INSECURE_WRANGLER, encoding="utf-8")
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"hono": "^4.0.0"}}', encoding="utf-8"
        )
        analyzer = HonoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "wrangler_secret" in kinds
        assert "host_exposed" in kinds
        assert "nodejs_compat" in kinds

    def test_hardened_hono_app_scores_well(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.ts").write_text(HARDENED_HONO_APP, encoding="utf-8")
        analyzer = HonoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = HonoAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no application" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = HonoFinding(
            kind="test",
            severity="high",
            message="test message",
            path="src/index.ts",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.ts").write_text(HARDENED_HONO_APP, encoding="utf-8")
        analyzer = HonoAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Hono application analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = HonoAnalyzer(".").generate_hardened_template()
        assert "secureHeaders" in template
        assert "process.env.ADMIN_TOKEN" in template
