"""Tests for ExpressAnalyzer."""

from pathlib import Path

from devai.express_analyzer import ExpressAnalyzer, ExpressFinding


INSECURE_EXPRESS_APP = """\
import express from 'express';
import cors from 'cors';
import session from 'express-session';

const app = express();
app.set('trust proxy', true);

app.use(cors({ origin: '*' }));
app.use(session({
  secret: 'hardcoded_session_secret_value',
  saveUninitialized: true,
  resave: true,
  cookie: { secure: false, httpOnly: false },
}));
app.use(express.json({ limit: 'infinity' }));

app.get('/admin/users', (req, res) => res.json({ users: [] }));
app.get('/debug/env', (req, res) => res.json(process.env));

app.get('/proxy', async (req, res) => {
  const result = await fetch('http://10.0.0.1:8080/internal');
  res.json(await result.json());
});

app.listen(3000, '0.0.0.0');
"""

HARDENED_EXPRESS_APP = """\
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', false);

app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 100 }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN ?? 'https://example.com',
}));
app.use(express.json({ limit: '1mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET ?? '',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: 'strict' },
}));

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? '127.0.0.1';
app.listen(port, host);
"""


class TestExpressAnalyzer:
    def test_detects_insecure_express_app(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.ts").write_text(INSECURE_EXPRESS_APP, encoding="utf-8")
        analyzer = ExpressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "cors_wildcard" in kinds
        assert "session_secret_hardcoded" in kinds
        assert "unprotected_admin_route" in kinds
        assert "proxy_internal" in kinds
        assert "host_exposed" in kinds
        assert "save_uninitialized" in kinds
        assert "cookie_insecure" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_express_app_scores_well(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.ts").write_text(HARDENED_EXPRESS_APP, encoding="utf-8")
        analyzer = ExpressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_detects_via_package_json(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"express": "^4.18.0", "cors": "^2.8.5"}}',
            encoding="utf-8",
        )
        (tmp_path / "server.js").write_text(
            "const express = require('express');\n"
            "const cors = require('cors');\n"
            "const app = express();\n"
            "app.use(cors({ origin: '*' }));\n",
            encoding="utf-8",
        )
        analyzer = ExpressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "cors_wildcard" in kinds

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = ExpressAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no application" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = ExpressFinding(
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
        (tmp_path / "src" / "index.ts").write_text(HARDENED_EXPRESS_APP, encoding="utf-8")
        analyzer = ExpressAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Express application analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = ExpressAnalyzer(".").generate_hardened_template()
        assert "helmet" in template
        assert "process.env.SESSION_SECRET" in template
