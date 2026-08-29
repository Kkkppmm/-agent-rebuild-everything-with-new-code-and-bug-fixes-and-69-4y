"""Tests for CypressAnalyzer."""

import json
from pathlib import Path

from devai.cypress_analyzer import CypressAnalyzer, CypressFinding


INSECURE_CYPRESS_CONFIG = """\
import { defineConfig } from "cypress";

export default defineConfig({
  e2e: {
    baseUrl: "http://insecure.example.com",
    chromeWebSecurity: false,
    experimentalModifyObstructiveThirdPartyCode: true,
    supportFile: "../.ssh/cypress-support.js",
    screenshotsFolder: "/tmp/cypress-screenshots",
    watchForFileChanges: true,
    experimentalRunAllSpecs: true,
    env: {
      api_key: "hardcoded_secret_value_12345",
    },
  },
});
"""

HARDENED_CYPRESS = """\
import { defineConfig } from "cypress";

export default defineConfig({
  e2e: {
    baseUrl: "http://localhost:3000",
    chromeWebSecurity: true,
    watchForFileChanges: false,
  },
});
"""


class TestCypressAnalyzer:
    def test_detects_insecure_cypress_config(self, tmp_path: Path):
        (tmp_path / "cypress.config.ts").write_text(INSECURE_CYPRESS_CONFIG, encoding="utf-8")
        analyzer = CypressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "chrome_web_security_off" in kinds
        assert "insecure_http" in kinds
        assert "fixtures_outside" in kinds
        assert "artifact_leak" in kinds
        assert "modify_obstructive_code" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_legacy_cypress_json(self, tmp_path: Path):
        (tmp_path / "cypress.json").write_text(
            '{"baseUrl": "http://insecure.example.com", "chromeWebSecurity": false}',
            encoding="utf-8",
        )
        analyzer = CypressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "chrome_web_security_off" in kinds
        assert "insecure_http" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "cypress.config.js").write_text(HARDENED_CYPRESS, encoding="utf-8")
        analyzer = CypressAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = CypressAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Cypress configs: none found"

    def test_detects_package_json_cypress_block(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"cypress": {"chromeWebSecurity": False}}),
            encoding="utf-8",
        )
        analyzer = CypressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "chrome_web_security_off" in kinds

    def test_finding_format(self):
        finding = CypressFinding(
            kind="chrome_web_security_off",
            severity="high",
            message="test",
            path="cypress.config.ts",
            lineno=6,
        )
        assert "[high] cypress.config.ts:6" in finding.format()

    def test_generate_hardened_template(self):
        template = CypressAnalyzer(".").generate_hardened_template()
        assert "chromeWebSecurity: true" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "cypress.config.ts").write_text(INSECURE_CYPRESS_CONFIG, encoding="utf-8")
        context = CypressAnalyzer(str(tmp_path)).to_context()
        assert "Cypress analysis:" in context
        assert "health score:" in context
