"""Tests for JestAnalyzer."""

import json
from pathlib import Path

from devai.jest_analyzer import JestAnalyzer, JestFinding


INSECURE_JEST_CONFIG = """\
module.exports = {
  preset: "http://insecure.example.com/jest-preset",
  globalSetup: "./scripts/setup.sh",
  setupFilesAfterEnv: ["<rootDir>/setup-eval.js"],
  testPathIgnorePatterns: ["/node_modules/", "/security/", "/auth/"],
  moduleNameMapper: {
    "^@secrets/(.*)$": "<rootDir>/../.ssh/$1",
  },
  haste: { enableSymlinks: true },
  clearMocks: false,
  bail: false,
  reporters: ["default", ["jest-junit", { outputDirectory: "/tmp" }]],
};
"""

INSECURE_SETUP = """\
eval('process.env.SECRET = "leaked"');
const token = "api_key=hardcoded_secret_value_12345";
"""

INSECURE_PACKAGE_JSON = {
    "name": "demo",
    "jest": {
        "testEnvironment": "node",
        "globalSetup": "./setup-eval.js",
        "collectCoverageFrom": [],
    },
}

HARDENED_JEST = """\
module.exports = {
  testEnvironment: "node",
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  bail: process.env.CI ? 1 : 0,
};
"""


class TestJestAnalyzer:
    def test_detects_insecure_jest_config(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text(INSECURE_JEST_CONFIG, encoding="utf-8")
        analyzer = JestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "security_tests_ignored" in kinds
        assert "module_mapper_redirect" in kinds
        assert "symlinks_enabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_eval_in_setup_reference(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text(
            'module.exports = { setupFiles: ["./setup-eval.js"] };\n'
            "eval('process.env.SECRET = \"leaked\"');\n",
            encoding="utf-8",
        )
        analyzer = JestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "eval_usage" in kinds

    def test_detects_package_json_jest_block(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps(INSECURE_PACKAGE_JSON, indent=2), encoding="utf-8"
        )
        analyzer = JestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "coverage_disabled" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text(HARDENED_JEST, encoding="utf-8")
        analyzer = JestAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = JestAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Jest configs: none found"

    def test_finding_format(self):
        finding = JestFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="jest.config.js",
            lineno=2,
        )
        assert "[high] jest.config.js:2" in finding.format()

    def test_generate_hardened_template(self):
        template = JestAnalyzer(".").generate_hardened_template()
        assert "clearMocks" in template
        assert "enableSymlinks: false" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text(INSECURE_JEST_CONFIG, encoding="utf-8")
        context = JestAnalyzer(str(tmp_path)).to_context()
        assert "Jest analysis:" in context
        assert "health score:" in context
