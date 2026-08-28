"""Tests for RuboCopAnalyzer."""

from pathlib import Path

from devai.rubocop_analyzer import RuboCopAnalyzer, RuboCopFinding


INSECURE_CONFIG = """\
inherit_from:
  - http://example.com/rubocop.yml
  - https://raw.githubusercontent.com/org/repo/main/.rubocop.yml

require:
  - rubocop-custom

AllCops:
  NewCops: disable
  TargetRubyVersion: 2.3
  DisabledByDefault: true
  RunRailsCops: false
  Exclude:
    - 'lib/**/*'
    - 'app/**/*'
    - '**/*'
  api_key: hardcoded_secret_value_12345

Security/Eval:
  Enabled: false

Security/YAMLLoad:
  Enabled: false

Bundler/InsecureRubyProtocol:
  Enabled: false

Rails/ContentSecurityPolicy:
  Enabled: false
"""

HARDENED_CONFIG = """\
AllCops:
  NewCops: enable
  TargetRubyVersion: 3.3
  Exclude:
    - 'vendor/**/*'
    - 'tmp/**/*'

require:
  - rubocop-rails
  - rubocop-security

Security/Eval:
  Enabled: true

Bundler/InsecureRubyProtocol:
  Enabled: true
"""


class TestRuboCopAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / ".rubocop.yml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = RuboCopAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "disabled_by_default" in kinds
        assert "security_cop_disabled" in kinds
        assert "exclude_source" in kinds
        assert "exclude_broad" in kinds
        assert "inherit_insecure_http" in kinds
        assert "inherit_remote" in kinds
        assert "new_cops_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".rubocop.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = RuboCopAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 80.0

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = RuboCopAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = RuboCopFinding(
            kind="disabled_by_default",
            severity="high",
            message="test message",
            path=".rubocop.yml",
            lineno=10,
            line="  DisabledByDefault: true",
        )
        assert "[high]" in finding.format()
        assert ".rubocop.yml:10" in finding.format()

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = RuboCopAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "Security/Eval" in template
        assert "NewCops: enable" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".rubocop.yml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = RuboCopAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "RuboCop analysis:" in context
        assert "Security" in context or "DisabledByDefault" in context

    def test_supports_yaml_names(self, tmp_path: Path):
        (tmp_path / "rubocop.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = RuboCopAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1
        assert analyzer.config_files()[0].name == "rubocop.yaml"
