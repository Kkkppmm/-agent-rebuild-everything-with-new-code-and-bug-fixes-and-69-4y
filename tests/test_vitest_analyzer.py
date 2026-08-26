"""Tests for VitestAnalyzer."""

import json
from pathlib import Path

from devai.vitest_analyzer import VitestAnalyzer, VitestFinding


INSECURE_VITEST_CONFIG = """\
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    passWithNoTests: false,
    dangerouslyIgnoreUnhandledErrors: true,
    setupFiles: ['https://evil.example.com/setup.js'],
    env: {
      API_KEY: 'hardcoded-secret-value',
      DATABASE_URL: 'postgres://user:pass@db.example.com/app',
    },
  },
  server: {
    fs: {
      strict: false,
      allow: ['..', '/etc'],
    },
    host: true,
  },
});
"""

INSECURE_VITE_CONFIG = """\
import { defineConfig } from 'vite';

export default defineConfig({
  test: {
  },
  server: {
    proxy: {
      '/api': 'http://insecure-proxy.example.com',
    },
  },
});
"""

HARDENED_VITEST_CONFIG = """\
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    passWithNoTests: true,
    setupFiles: ['./test/setup.ts'],
  },
  server: {
    fs: {
      strict: true,
      allow: [process.cwd()],
    },
  },
});
"""


class TestVitestAnalyzer:
    def test_detects_insecure_vitest_config(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(INSECURE_VITEST_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "fs_strict_disabled" in kinds
        assert "remote_setup_file" in kinds
        assert "ignore_unhandled_errors" in kinds
        assert "hardcoded_secret" in kinds or "sensitive_env" in kinds

    def test_detects_insecure_vite_test_block(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"devDependencies": {"vitest": "^2.0.0"}}),
            encoding="utf-8",
        )
        (tmp_path / "vite.config.ts").write_text(INSECURE_VITE_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_proxy" in kinds or "insecure_http" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(HARDENED_VITEST_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_no_configs_returns_full_health(self, tmp_path: Path):
        analyzer = VitestAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.configs == 0

    def test_generate_hardened_config(self):
        config = VitestAnalyzer(".").generate_hardened_config()
        assert "strict: true" in config
        assert "dangerouslyIgnoreUnhandledErrors: false" in config

    def test_finding_format(self):
        finding = VitestFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="vitest.config.ts",
            lineno=10,
        )
        assert "[high]" in finding.format()
        assert "vitest.config.ts:10" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(INSECURE_VITEST_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        assert "Vitest configs:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Vitest analysis:" in context
        assert "health score:" in context
