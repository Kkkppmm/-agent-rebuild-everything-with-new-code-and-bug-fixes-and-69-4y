"""Tests for ESLintAnalyzer."""

from pathlib import Path

from devai.eslint_analyzer import ESLintAnalyzer, ESLintFinding


INSECURE_ESLINTRC = """\
{
  "extends": [
    "eslint:recommended",
    "http://evil.example.com/eslint-config.js"
  ],
  "plugins": ["security"],
  "env": {
    "browser": true,
    "node": true
  },
  "rules": {
    "no-eval": "off",
    "no-implied-eval": 0,
    "security/detect-eval-with-expression": false
  },
  "globals": {
    "eval": true
  }
}
"""

INSECURE_JS_CONFIG = """\
// eslint.config.js
export default [
  {
    rules: {
      api_key: "sk-live-hardcoded-secret-token-12345",
      "no-new-func": "off"
    }
  }
];
"""

HARDENED_ESLINTRC = """\
{
  "root": true,
  "extends": ["eslint:recommended", "plugin:security/recommended"],
  "rules": {
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "error"
  }
}
"""


class TestESLintAnalyzer:
    def test_detects_insecure_eslintrc(self, tmp_path: Path):
        (tmp_path / ".eslintrc.json").write_text(INSECURE_ESLINTRC, encoding="utf-8")
        analyzer = ESLintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "disabled_security_rule" in kinds
        assert analyzer.stats.high_severity >= 1

    def test_detects_insecure_js_config(self, tmp_path: Path):
        (tmp_path / "eslint.config.js").write_text(INSECURE_JS_CONFIG, encoding="utf-8")
        analyzer = ESLintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "disabled_security_rule" in kinds

    def test_detects_package_json_eslint_config(self, tmp_path: Path):
        pkg = """\
{
  "name": "demo",
  "eslintConfig": {
    "extends": "http://insecure.example.com/config",
    "rules": { "no-eval": "off" }
  }
}
"""
        (tmp_path / "package.json").write_text(pkg, encoding="utf-8")
        analyzer = ESLintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "disabled_security_rule" in kinds

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / ".eslintrc.json").write_text(HARDENED_ESLINTRC, encoding="utf-8")
        analyzer = ESLintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = ESLintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "ESLint: no config files found"

    def test_generate_hardened_template(self):
        config = ESLintAnalyzer(".").generate_hardened_template()
        assert "no-eval" in config
        assert "eslint-plugin-security" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".eslintrc.json").write_text(INSECURE_ESLINTRC, encoding="utf-8")
        analyzer = ESLintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "ESLint configuration analysis:" in context
        assert "insecure" in context.lower() or "disabled" in context.lower()

    def test_finding_format(self):
        finding = ESLintFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".eslintrc.json",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert ".eslintrc.json:1" in finding.format()
