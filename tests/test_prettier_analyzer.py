"""Tests for PrettierAnalyzer."""

from pathlib import Path

from devai.prettier_analyzer import PrettierAnalyzer, PrettierFinding


INSECURE_PRETTIERRC = """\
{
  "semi": true,
  "plugins": [
    "http://evil.example.com/prettier-plugin-evil.js"
  ],
  "api_key": "sk-live-hardcoded-secret-token-12345"
}
"""

INSECURE_JS_CONFIG = """\
// prettier.config.js
module.exports = {
  plugins: [require("http://evil.example.com/plugin.js")],
  process_env: process.env.API_SECRET_TOKEN
};
"""

HARDENED_PRETTIERRC = """\
{
  "semi": true,
  "singleQuote": true,
  "trailingComma": "all",
  "printWidth": 100
}
"""


class TestPrettierAnalyzer:
    def test_detects_insecure_prettierrc(self, tmp_path: Path):
        (tmp_path / ".prettierrc.json").write_text(INSECURE_PRETTIERRC, encoding="utf-8")
        analyzer = PrettierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.stats.high_severity >= 1

    def test_detects_insecure_js_config(self, tmp_path: Path):
        (tmp_path / "prettier.config.js").write_text(INSECURE_JS_CONFIG, encoding="utf-8")
        analyzer = PrettierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds or "insecure_plugin" in kinds
        assert "secret_env_reference" in kinds

    def test_detects_package_json_prettier_config(self, tmp_path: Path):
        pkg = """\
{
  "name": "demo",
  "prettier": {
    "plugins": ["http://insecure.example.com/plugin.js"]
  }
}
"""
        (tmp_path / "package.json").write_text(pkg, encoding="utf-8")
        analyzer = PrettierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / ".prettierrc.json").write_text(HARDENED_PRETTIERRC, encoding="utf-8")
        analyzer = PrettierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = PrettierAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Prettier: no config files found"

    def test_generate_hardened_template(self):
        config = PrettierAnalyzer(".").generate_hardened_template()
        assert "trailingComma" in config
        assert "printWidth" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".prettierrc.json").write_text(INSECURE_PRETTIERRC, encoding="utf-8")
        analyzer = PrettierAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Prettier configuration analysis:" in context
        assert "insecure" in context.lower() or "hardcoded" in context.lower()

    def test_finding_format(self):
        finding = PrettierFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".prettierrc.json",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert ".prettierrc.json:1" in finding.format()
