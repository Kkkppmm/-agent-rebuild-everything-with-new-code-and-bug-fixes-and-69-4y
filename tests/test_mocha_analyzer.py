"""Tests for MochaAnalyzer."""

import json
from pathlib import Path

from devai.mocha_analyzer import MochaAnalyzer, MochaFinding


INSECURE_MOCHA_CONFIG = """\
{
  "require": ["../.ssh/setup.js"],
  "allowUncaught": true,
  "forbidOnly": false,
  "timeout": 0,
  "grep": "/security/",
  "invert": true,
  "reporter": "mocha-junit-reporter",
  "reporter-option": ["mochaFile=http://insecure.example.com/results.xml"]
}
"""

INSECURE_MOCHA_JS = """\
module.exports = {
  require: ["./setup-eval.js"],
  bail: false,
};
eval('process.env.SECRET = "leaked"');
const token = "api_key=hardcoded_secret_value_12345";
"""

HARDENED_MOCHA = """\
{
  "timeout": 10000,
  "bail": true,
  "forbidOnly": true,
  "allowUncaught": false
}
"""


class TestMochaAnalyzer:
    def test_detects_insecure_mocharc(self, tmp_path: Path):
        (tmp_path / ".mocharc.json").write_text(INSECURE_MOCHA_CONFIG, encoding="utf-8")
        analyzer = MochaAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "require_outside_project" in kinds
        assert "allow_uncaught" in kinds
        assert "forbid_only_disabled" in kinds
        assert "timeout_zero" in kinds
        assert "security_tests_ignored" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_eval_in_config(self, tmp_path: Path):
        (tmp_path / ".mocharc.js").write_text(INSECURE_MOCHA_JS, encoding="utf-8")
        analyzer = MochaAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "eval_usage" in kinds
        assert "hardcoded_secret" in kinds

    def test_detects_package_json_mocha_block(self, tmp_path: Path):
        pkg = {"name": "demo", "mocha": {"timeout": 0, "forbidOnly": False}}
        (tmp_path / "package.json").write_text(json.dumps(pkg, indent=2), encoding="utf-8")
        analyzer = MochaAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "timeout_zero" in kinds
        assert "forbid_only_disabled" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".mocharc.json").write_text(HARDENED_MOCHA, encoding="utf-8")
        analyzer = MochaAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = MochaAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Mocha configs: none found"

    def test_finding_format(self):
        finding = MochaFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path=".mocharc.json",
            lineno=2,
        )
        assert "[high] .mocharc.json:2" in finding.format()

    def test_generate_hardened_template(self):
        template = MochaAnalyzer(".").generate_hardened_template()
        assert "forbidOnly" in template
        assert "allowUncaught" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".mocharc.json").write_text(INSECURE_MOCHA_CONFIG, encoding="utf-8")
        context = MochaAnalyzer(str(tmp_path)).to_context()
        assert "Mocha analysis:" in context
        assert "health score:" in context
