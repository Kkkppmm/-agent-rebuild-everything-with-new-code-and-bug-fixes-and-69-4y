"""Tests for QwikAnalyzer."""

from pathlib import Path

from devai.qwik_analyzer import QwikAnalyzer, QwikFinding


INSECURE_QWIK_CONFIG = """\
import { defineConfig } from '@builder.io/qwik-city/vite';

export default defineConfig(() => ({
  server: {
    host: '0.0.0.0',
    origin: ['*'],
    checkOrigin: false,
    csrfProtection: false,
    trustedOrigins: ['*'],
    proxy: {
      '/api': { target: 'http://192.168.1.1:8080' },
    },
  },
  adapter: {
    name: 'cloudflare-pages',
    config: {
      accountId: 'hardcoded_account_id_value',
      apiToken: 'hardcoded_api_token_value',
    },
  },
  build: {
    sourcemap: true,
  },
  devtools: true,
  prefetchStrategy: 'all',
  basePathname: '../outside',
  api_key: 'api_key=hardcoded_secret_value_12345',
  headers: {
    'Access-Control-Allow-Origin': '*',
  },
  tls: { rejectUnauthorized: false },
}));
"""

HARDENED_QWIK_CONFIG = """\
import { defineConfig } from '@builder.io/qwik-city/vite';
import { qwikVite } from '@builder.io/qwik/optimizer';

export default defineConfig(() => ({
  plugins: [qwikVite()],
  server: {
    host: 'localhost',
    strictPort: true,
    origin: 'https://localhost:5173',
  },
  preview: {
    host: 'localhost',
    strictPort: true,
  },
  build: {
    sourcemap: false,
  },
}));
"""


class TestQwikAnalyzer:
    def test_finds_insecure_config(self, tmp_path: Path):
        (tmp_path / "qwik.config.ts").write_text(INSECURE_QWIK_CONFIG, encoding="utf-8")
        analyzer = QwikAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "host_exposed" in kinds
        assert "origin_wildcard" in kinds or "trusted_origins_wildcard" in kinds
        assert "origin_check_disabled" in kinds
        assert "csrf_disabled" in kinds
        assert "proxy_internal" in kinds
        assert "adapter_credential" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "path_traversal" in kinds
        assert analyzer.stats.configs == 1
        assert analyzer.stats.high_severity > 0
        assert analyzer.health_score() < 100.0

    def test_hardened_config_clean(self, tmp_path: Path):
        (tmp_path / "qwik.config.ts").write_text(HARDENED_QWIK_CONFIG, encoding="utf-8")
        analyzer = QwikAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = QwikAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.summary() == "Qwik: no configuration files found"

    def test_finding_format(self):
        finding = QwikFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="qwik.config.ts",
            lineno=5,
            line="api_key: 'secret'",
        )
        assert "[high]" in finding.format()
        assert "qwik.config.ts:5" in finding.format()

    def test_generate_hardened_template(self):
        template = QwikAnalyzer(".").generate_hardened_template()
        assert "QwikAnalyzer" in template
        assert "sourcemap: false" in template
        assert "localhost" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "qwik.config.ts").write_text(INSECURE_QWIK_CONFIG, encoding="utf-8")
        analyzer = QwikAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Qwik configuration analysis" in context
        assert "health score" in context

    def test_discovers_qwik_city_config(self, tmp_path: Path):
        (tmp_path / "qwik-city.config.ts").write_text(HARDENED_QWIK_CONFIG, encoding="utf-8")
        analyzer = QwikAnalyzer(str(tmp_path))
        assert len(analyzer.configs()) == 1

    def test_summary_with_findings(self, tmp_path: Path):
        (tmp_path / "qwik.config.ts").write_text(INSECURE_QWIK_CONFIG, encoding="utf-8")
        analyzer = QwikAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Qwik:" in summary
        assert "finding" in summary
