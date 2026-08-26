"""Tests for PlaywrightAnalyzer."""

import json
from pathlib import Path

from devai.playwright_analyzer import PlaywrightAnalyzer, PlaywrightFinding


INSECURE_PLAYWRIGHT_CONFIG = """\
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  use: {
    baseURL: "http://evil.example.com",
    ignoreHTTPSErrors: true,
    bypassCSP: true,
    headed: true,
    devtools: true,
    trace: "on",
    video: "on",
    storageState: "./fixtures/auth-session-with-token.json",
    proxy: { server: "http://proxy:8080", username: "user", password: "secret123" },
    launchOptions: {
      args: ["--no-sandbox", "--remote-debugging-address=0.0.0.0"],
    },
    permissions: ["clipboard-read", "geolocation", "notifications"],
  },
  recordHar: { mode: "on", path: "./har/output.har" },
  webServer: {
    url: "http://staging.internal.example.com",
    reuseExistingServer: true,
  },
});
"""

INSECURE_EVAL_CONFIG = """\
import { defineConfig } from "@playwright/test";
eval('process.env.SECRET = "leaked"');
export default defineConfig({});
"""

PACKAGE_WITH_PLAYWRIGHT = {
    "name": "demo",
    "devDependencies": {"@playwright/test": "^1.48.0"},
}

HARDENED_PLAYWRIGHT = """\
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  forbidOnly: !!process.env.CI,
  use: {
    baseURL: process.env.BASE_URL || "http://localhost:3000",
    ignoreHTTPSErrors: false,
    bypassCSP: false,
    headless: true,
    trace: "on-first-retry",
    video: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
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
        assert "ignore_https_errors" in kinds
        assert "bypass_csp" in kinds
        assert "no_sandbox" in kinds
        assert "remote_debug" in kinds
        assert "trace_always_on" in kinds
        assert "video_always_on" in kinds
        assert "proxy_credentials" in kinds
        assert analyzer.health_score() < 40.0

    def test_detects_eval_in_config(self, tmp_path: Path):
        (tmp_path / "playwright.config.ts").write_text(
            INSECURE_EVAL_CONFIG, encoding="utf-8"
        )
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "eval_usage" in kinds

    def test_detects_package_json_with_playwright_dep(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps(PACKAGE_WITH_PLAYWRIGHT, indent=2), encoding="utf-8"
        )
        (tmp_path / "playwright.config.ts").write_text(
            INSECURE_PLAYWRIGHT_CONFIG, encoding="utf-8"
        )
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        paths = analyzer.config_files()
        assert any(p.name == "package.json" for p in paths)
        assert len(analyzer.analyze()) > 0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "playwright.config.ts").write_text(
            HARDENED_PLAYWRIGHT, encoding="utf-8"
        )
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Playwright configs: none found"

    def test_finding_format(self):
        finding = PlaywrightFinding(
            kind="ignore_https_errors",
            severity="high",
            message="test",
            path="playwright.config.ts",
            lineno=5,
        )
        assert "[high] playwright.config.ts:5" in finding.format()

    def test_generate_hardened_template(self):
        template = PlaywrightAnalyzer(".").generate_hardened_template()
        assert "ignoreHTTPSErrors: false" in template
        assert "trace: \"on-first-retry\"" in template
        assert "forbidOnly: !!process.env.CI" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "playwright.config.ts").write_text(
            INSECURE_PLAYWRIGHT_CONFIG, encoding="utf-8"
        )
        context = PlaywrightAnalyzer(str(tmp_path)).to_context()
        assert "Playwright analysis:" in context
        assert "health score:" in context
