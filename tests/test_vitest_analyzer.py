"""Tests for VitestAnalyzer."""

import json
from pathlib import Path

from devai.vitest_analyzer import VitestAnalyzer, VitestFinding


INSECURE_VITEST_CONFIG = """\
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    allowOnly: true,
    dangerouslyIgnoreUnhandledErrors: true,
    clearMocks: false,
    poolOptions: {
      forks: { execArgv: ["--inspect=0.0.0.0:9229"] },
    },
    coverage: { exclude: ["**"] },
    deps: { inline: ["*"] },
  },
  server: {
    fs: { allow: ["..", "/etc"] },
  },
});
"""

INSECURE_VITE_CONFIG = """\
import { defineConfig } from "vite";

export default defineConfig({
  test: {
    setupFiles: ["./setup-eval.ts"],
    environment: "jsdom",
    eval('process.env.SECRET = "leaked"');
  },
});
"""

INSECURE_SETUP = """\
eval('process.env.SECRET = "leaked"');
const api_key = "hardcoded_secret_value_12345";
"""

PACKAGE_WITH_VITEST = {
    "name": "demo",
    "devDependencies": {"vitest": "^2.0.0"},
    "vitest": {
        "allowOnly": True,
        "dangerouslyIgnoreUnhandledErrors": True,
    },
}

HARDENED_VITEST = """\
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: false,
    clearMocks: true,
    mockReset: true,
    restoreMocks: true,
    allowOnly: !process.env.CI,
    dangerouslyIgnoreUnhandledErrors: false,
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
        assert "allow_only_enabled" in kinds
        assert "fs_parent_traversal" in kinds
        assert "remote_inspect" in kinds
        assert analyzer.health_score() < 40.0

    def test_detects_vite_config_test_block(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"devDependencies": {"vitest": "^2.0.0"}}, indent=2),
            encoding="utf-8",
        )
        (tmp_path / "vite.config.ts").write_text(INSECURE_VITE_CONFIG, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "eval_usage" in kinds

    def test_detects_package_json_vitest_block(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps(PACKAGE_WITH_VITEST, indent=2), encoding="utf-8"
        )
        analyzer = VitestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "ignore_unhandled_errors" in kinds
        assert "allow_only_enabled" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(HARDENED_VITEST, encoding="utf-8")
        analyzer = VitestAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = VitestAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Vitest configs: none found"

    def test_finding_format(self):
        finding = VitestFinding(
            kind="ignore_unhandled_errors",
            severity="high",
            message="test",
            path="vitest.config.ts",
            lineno=5,
        )
        assert "[high] vitest.config.ts:5" in finding.format()

    def test_generate_hardened_template(self):
        template = VitestAnalyzer(".").generate_hardened_template()
        assert "dangerouslyIgnoreUnhandledErrors: false" in template
        assert "globals: false" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "vitest.config.ts").write_text(INSECURE_VITEST_CONFIG, encoding="utf-8")
        context = VitestAnalyzer(str(tmp_path)).to_context()
        assert "Vitest analysis:" in context
        assert "health score:" in context
