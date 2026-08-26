"""Tests for v6.89.0 FalcoAnalyzer integration."""

from pathlib import Path

from devai import DevAI, FalcoAnalyzer
from devai.project_health import ProjectHealth


HARDENED_RULES = """\
- macro: shell_procs
  condition: proc.name in (bash, sh, zsh)

- list: user_expected_shell_activity
  items: []

- rule: Detect shell in container
  desc: Detect an attempt to spawn a shell inside a container
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_shell_activity
  output: >
    Shell spawned in container (user=%user.name container=%container.name
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, mitre_execution]
  source: syscall
"""

UNSAFE_RULES = """\
- rule: Catch everything
  desc: Overly broad detection
  condition: evt.type=*
  output: none
  priority: DEBUG
  enabled: false
  skip-if-evidence: true
  append: false
  suppress:
    - "*"
webhook_url: http://insecure.example.com/falco
api_key: supersecret123
"""

DISABLED_RULE = """\
- rule: Disabled detection
  desc: Security rule turned off
  condition: spawned_process and container
  output: Disabled rule fired
  priority: WARNING
  enabled: false
"""


class TestFalcoAnalyzer:
    def test_finds_no_high_issues_in_hardened_rules(self, tmp_path: Path):
        rules = tmp_path / "falco_rules.yaml"
        rules.write_text(HARDENED_RULES, encoding="utf-8")
        analyzer = FalcoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.rules_files == 1
        assert analyzer.stats.findings == 0
        assert analyzer.health_score() == 100.0

    def test_detects_unsafe_rules(self, tmp_path: Path):
        rules = tmp_path / "custom_falco.yaml"
        rules.write_text(UNSAFE_RULES, encoding="utf-8")
        analyzer = FalcoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "disabled_rule" in kinds
        assert "wildcard_condition" in kinds
        assert "wildcard_suppress" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.stats.high_severity >= 3
        assert analyzer.health_score() < 50.0

    def test_detects_disabled_rule(self, tmp_path: Path):
        rules = tmp_path / "falco_rules.yaml"
        rules.write_text(DISABLED_RULE, encoding="utf-8")
        analyzer = FalcoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        disabled = [f for f in findings if f.kind == "disabled_rule"]
        assert len(disabled) == 1
        assert disabled[0].severity == "high"

    def test_summary_and_context(self, tmp_path: Path):
        rules = tmp_path / "falco_rules.yaml"
        rules.write_text(HARDENED_RULES, encoding="utf-8")
        analyzer = FalcoAnalyzer(str(tmp_path))
        assert "Falco:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Falco rules analysis:" in context
        assert "rules=1" in context

    def test_generate_hardened_template(self):
        template = FalcoAnalyzer().generate_hardened_template()
        assert "- rule:" in template
        assert "priority: WARNING" in template

    def test_devai_facade(self):
        analyzer = DevAI.mock().falco(".")
        assert isinstance(analyzer, FalcoAnalyzer)

    def test_project_health_integration(self, tmp_path: Path):
        rules = tmp_path / "falco_rules.yaml"
        rules.write_text(HARDENED_RULES, encoding="utf-8")
        health = ProjectHealth(str(tmp_path), scan_secrets=False)
        report = health.analyze()
        falco_cat = next((c for c in report.categories if c.name == "falco"), None)
        assert falco_cat is not None
        assert falco_cat.score == 100.0
