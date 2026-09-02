"""Tests for FastifyAnalyzer."""

from pathlib import Path

from devai.fastify_analyzer import FastifyAnalyzer, FastifyFinding


INSECURE_FASTIFY_APP = """\
import Fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import basicAuth from '@fastify/basic-auth';

const fastify = Fastify({
  trustProxy: true,
  bodyLimit: 0,
});

await fastify.register(cors, { origin: true });
await fastify.register(jwt, { secret: 'jwt_secret_hardcoded_value' });
await fastify.register(basicAuth, {
  username: 'admin',
  password: 'super_secret_password',
  validate: async (username, password) => username === 'admin',
});

fastify.get('/admin/users', async () => ({ users: [] }));
fastify.get('/debug/env', async () => process.env);

fastify.get('/proxy', async () => {
  const res = await fetch('http://10.0.0.1:8080/internal');
  return res.json();
});

await fastify.listen({ port: 3000, host: '0.0.0.0' });
"""

HARDENED_FASTIFY_APP = """\
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import jwt from '@fastify/jwt';

const fastify = Fastify({
  logger: true,
  trustProxy: false,
  bodyLimit: 1_048_576,
});

await fastify.register(helmet);
await fastify.register(rateLimit, { max: 100, timeWindow: '1 minute' });
await fastify.register(cors, {
  origin: process.env.ALLOWED_ORIGIN ?? 'https://example.com',
});
await fastify.register(jwt, { secret: process.env.JWT_SECRET ?? '' });

fastify.get('/health', async () => ({ status: 'ok' }));

await fastify.listen({
  port: Number(process.env.PORT ?? 3000),
  host: process.env.HOST ?? '127.0.0.1',
});
"""


class TestFastifyAnalyzer:
    def test_detects_insecure_fastify_app(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.ts").write_text(INSECURE_FASTIFY_APP, encoding="utf-8")
        analyzer = FastifyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "cors_wildcard" in kinds
        assert "jwt_secret_hardcoded" in kinds
        assert "basic_auth_hardcoded" in kinds
        assert "unprotected_admin_route" in kinds
        assert "proxy_internal" in kinds
        assert "host_exposed" in kinds
        assert "body_limit_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_fastify_app_scores_well(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.ts").write_text(HARDENED_FASTIFY_APP, encoding="utf-8")
        analyzer = FastifyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_detects_via_package_json(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"fastify": "^5.0.0", "@fastify/cors": "^10.0.0"}}',
            encoding="utf-8",
        )
        (tmp_path / "server.js").write_text(
            "import Fastify from 'fastify';\n"
            "const app = Fastify();\n"
            "app.register(import('@fastify/cors'), { origin: '*' });\n",
            encoding="utf-8",
        )
        analyzer = FastifyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "cors_wildcard" in kinds

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = FastifyAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no application" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = FastifyFinding(
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
        (tmp_path / "src" / "index.ts").write_text(HARDENED_FASTIFY_APP, encoding="utf-8")
        analyzer = FastifyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Fastify application analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = FastifyAnalyzer(".").generate_hardened_template()
        assert "@fastify/helmet" in template
        assert "process.env.JWT_SECRET" in template
