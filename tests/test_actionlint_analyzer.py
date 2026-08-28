"""Tests for ActionlintAnalyzer."""

from pathlib import Path

from devai.actionlint_analyzer import ActionlintAnalyzer, ActionlintFinding


INSECURE_CONFIG = """\
self-hosted-runner:
  labels: []

config-variables:
  - DEPLOY_ENV

paths:
  .github/workflows/**/*.yaml:
    ignore:
      - 'shellcheck reported issue in this script: SC2086:.+'
      - 'the runner of ".+" action is too old to run on'
      - 'action version is not pinned'
      - 'permission write-all is too permissive'

api_key: hardcoded_secret_value_12345
"""

HARDENED_CONFIG = """\
self-hosted-runner:
  labels:
    - self-hosted
    - linux
    - x64

config-variables:
  - DEPLOY_ENV

paths: {}
"""

BROAD_IGNORE_CONFIG = """\
paths:
  .github/workflows/**:
    ignore:
      - '.+'
"""


class TestActionlintAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        github = tmp_path / ".github"
        github.mkdir()
        (github / "actionlint.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = ActionlintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "ignore_shellcheck_security" in kinds
        assert "ignore_runner_check" in kinds
        assert "ignore_action_pin" in kinds
        assert "ignore_permission_check" in kinds
        assert "ignore_broad_workflow" in kinds
        assert "empty_self_hosted_labels" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        github = tmp_path / ".github"
        github.mkdir()
        (github / "actionlint.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = ActionlintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].self_hosted_labels == ["self-hosted", "linux", "x64"]

    def test_broad_ignore_regex(self, tmp_path: Path):
        github = tmp_path / ".github"
        github.mkdir()
        (github / "actionlint.yaml").write_text(BROAD_IGNORE_CONFIG, encoding="utf-8")
        analyzer = ActionlintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "ignore_broad_regex" in kinds
        assert "ignore_broad_workflow" in kinds

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = ActionlintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = ActionlintFinding(
            kind="ignore_shellcheck_security",
            severity="high",
            message="ignore suppresses shellcheck security rule",
            path=".github/actionlint.yaml",
            lineno=8,
            line="      - 'shellcheck reported issue in this script: SC2086:.+'",
        )
        assert "[high] .github/actionlint.yaml:8" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = ActionlintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "self-hosted-runner:" in template
        assert "config-variables: []" in template

    def test_summary_and_context(self, tmp_path: Path):
        github = tmp_path / ".github"
        github.mkdir()
        (github / "actionlint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = ActionlintAnalyzer(str(tmp_path))
        assert "1 file(s)" in analyzer.summary()
        context = analyzer.to_context()
        assert "actionlint analysis:" in context
        assert "health score:" in context
