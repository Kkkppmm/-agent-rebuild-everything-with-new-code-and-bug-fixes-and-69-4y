"""Tests for WebdriverIOAnalyzer."""

from pathlib import Path

from devai.webdriverio_analyzer import WebdriverIOAnalyzer, WebdriverIOFinding


INSECURE_WDIO_CONFIG = """\
export const config = {
  runner: 'local',
  specs: ['../.ssh/**/*.spec.ts'],
  maxInstances: 50,
  baseUrl: 'http://insecure.example.com',
  protocol: 'http',
  capabilities: [{
    browserName: 'chrome',
    'goog:chromeOptions': {
      args: ['--no-sandbox', '--disable-web-security', '--remote-debugging-port=9222'],
    },
    acceptInsecureCerts: true,
  }],
  services: [{ user: 'admin', password: 'secret123' }],
  outputDir: '/tmp/wdio-results',
  headless: false,
};
"""

HARDENED_WDIO = """\
export const config = {
  runner: 'local',
  specs: ['./test/specs/**/*.ts'],
  maxInstances: 5,
  baseUrl: 'http://localhost:3000',
  capabilities: [{
    browserName: 'chrome',
    'goog:chromeOptions': { args: ['headless'] },
  }],
  outputDir: './test-results',
};
"""


class TestWebdriverIOAnalyzer:
    def test_detects_insecure_wdio_config(self, tmp_path: Path):
        (tmp_path / "wdio.conf.ts").write_text(INSECURE_WDIO_CONFIG, encoding="utf-8")
        analyzer = WebdriverIOAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "specs_outside_project" in kinds
        assert "accept_insecure_certs" in kinds
        assert "sandbox_disabled" in kinds
        assert "remote_debug" in kinds
        assert "insecure_http" in kinds
        assert "services_credentials" in kinds
        assert analyzer.health_score() < 30.0

    def test_detects_max_instances_high(self, tmp_path: Path):
        (tmp_path / "wdio.conf.js").write_text(
            "export const config = { maxInstances: 25 };\n", encoding="utf-8"
        )
        analyzer = WebdriverIOAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "max_instances_high" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "wdio.conf.ts").write_text(HARDENED_WDIO, encoding="utf-8")
        analyzer = WebdriverIOAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = WebdriverIOAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "WebdriverIO configs: none found"

    def test_finding_format(self):
        finding = WebdriverIOFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="wdio.conf.ts",
            lineno=2,
        )
        assert "[high] wdio.conf.ts:2" in finding.format()

    def test_generate_hardened_template(self):
        template = WebdriverIOAnalyzer(".").generate_hardened_template()
        assert "maxInstances" in template
        assert "headless" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "wdio.conf.ts").write_text(INSECURE_WDIO_CONFIG, encoding="utf-8")
        context = WebdriverIOAnalyzer(str(tmp_path)).to_context()
        assert "WebdriverIO analysis:" in context
        assert "health score:" in context
