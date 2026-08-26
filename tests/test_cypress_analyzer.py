"""Tests for CypressAnalyzer."""

from pathlib import Path

from devai.cypress_analyzer import CypressAnalyzer


INSECURE_CYPRESS_CONFIG = """\
import { defineConfig } from 'cypress';

export default defineConfig({
  e2e: {
    baseUrl: 'http://insecure.example.com',
    chromeWebSecurity: false,
    modifyObstructiveCode: true,
    video: true,
    screenshotsFolder: '/tmp/cypress-screenshots',
    videosFolder: '/var/www/public/videos',
    fileServerFolder: '../public',
    supportFile: 'cypress/support/eval-setup.js',
    hosts: { '*': '127.0.0.1' },
  },
});
"""

INSECURE_ENV = """\
{
  "API_KEY": "sk_live_hardcoded_secret_value_12345",
  "password": "super_secret_password"
}
"""

HARDENED_CYPRESS = """\
import { defineConfig } from 'cypress';

export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    chromeWebSecurity: true,
    video: false,
    screenshotsFolder: 'cypress/screenshots',
    videosFolder: 'cypress/videos',
  },
});
"""


class TestCypressAnalyzer:
    def test_detects_insecure_cypress_config(self, tmp_path: Path):
        (tmp_path / "cypress.config.ts").write_text(
            INSECURE_CYPRESS_CONFIG, encoding="utf-8"
        )
        analyzer = CypressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "chrome_web_security_off" in kinds
        assert "insecure_base_url" in kinds
        assert "modify_obstructive_code" in kinds
        assert "video_always_on" in kinds
        assert "public_artifact_dir" in kinds
        assert "file_server_outside" in kinds
        assert "hosts_bypass" in kinds
        assert analyzer.health_score() < 30.0

    def test_detects_secrets_in_env_file(self, tmp_path: Path):
        (tmp_path / "cypress.env.json").write_text(INSECURE_ENV, encoding="utf-8")
        analyzer = CypressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "env_secret" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "cypress.config.ts").write_text(
            HARDENED_CYPRESS, encoding="utf-8"
        )
        analyzer = CypressAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = CypressAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_generate_hardened_template(self):
        template = CypressAnalyzer(".").generate_hardened_template()
        assert "chromeWebSecurity: true" in template
        assert "video: false" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "cypress.config.js").write_text(
            "module.exports = { e2e: { chromeWebSecurity: false } };",
            encoding="utf-8",
        )
        analyzer = CypressAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Cypress analysis:" in context
