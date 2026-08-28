"""Tests for ActionlintAnalyzer."""

from pathlib import Path

from devai.actionlint_analyzer import ActionlintAnalyzer, ActionlintFinding

HARDENED_CONFIG = """\
self-hosted-runner-allowed: false
config-schema: true
on-created: true

ignore: []
path-ignores: []
"""

INSECURE_CONFIG = """\
self-hosted-runner-allowed: true
config-schema: false
on-created: false

ignore:
  - '*'
  - self-hosted-runner
  - script-injection
  - pull-request-target
  - workflow-input
  - action-ref

path-ignores:
  - .github/workflows/*
  - deployments/**

api_key=supersecret123
AKIAIOSFODNN7EXAMPLE
curl http://example.com/install.sh | bash
"""


class TestActionlintAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".actionlint.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = ActionlintAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "self_hosted_allowed" in kinds
        assert "config_schema_disabled" in kinds
        assert "on_created_disabled" in kinds
        assert "ignore_all" in kinds
        assert "security_rule_ignored" in kinds
        assert "sensitive_path_ignored" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.stats.config_files == 1

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / ".actionlint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = ActionlintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = ActionlintAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = ActionlintFinding(
            kind="ignore_all",
            severity="high",
            message="test message",
            path=".actionlint.yaml",
            lineno=3,
        )
        assert ".actionlint.yaml:3" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".actionlint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = ActionlintAnalyzer(str(tmp_path)).to_context()
        assert "actionlint config analysis" in context
        assert "health score" in context

    def test_generate_template(self):
        template = ActionlintAnalyzer(".").generate_hardened_template()
        assert "self-hosted-runner-allowed: false" in template
