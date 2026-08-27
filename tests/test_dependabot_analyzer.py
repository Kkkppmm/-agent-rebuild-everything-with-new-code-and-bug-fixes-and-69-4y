"""Tests for DependabotAnalyzer."""

from pathlib import Path

from devai.dependabot_analyzer import DependabotAnalyzer, DependabotFinding


INSECURE_CONFIG = """
version: 2
registries:
  private:
    type: npm-registry
    url: http://registry.example.com
    username: admin
    password: supersecret123
    token: ghp_hardcoded_github_token_value
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 50
    insecure-external-code-execution: allow
    registries:
      - private

  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 25
"""

HARDENED_CONFIG = """
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    groups:
      security-updates:
        applies-to: security-updates
        patterns:
          - "*"
    reviewers:
      - "security-team"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    groups:
      github-actions:
        patterns:
          - "*"
    reviewers:
      - "platform-team"
"""


def _write_dependabot_config(tmp_path: Path, content: str) -> Path:
    github_dir = tmp_path / ".github"
    github_dir.mkdir()
    path = github_dir / "dependabot.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestDependabotAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = DependabotAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_dependabot_config(tmp_path, INSECURE_CONFIG)
        analyzer = DependabotAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http_registry" in kinds
        assert "insecure_external_code" in kinds
        assert "daily_schedule" in kinds
        assert "high_pr_limit" in kinds
        assert "daily_schedule_all" in kinds
        assert "private_registry_no_reviewers" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_dependabot_config(tmp_path, HARDENED_CONFIG)
        analyzer = DependabotAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_dependabot_config(tmp_path, HARDENED_CONFIG)
        analyzer = DependabotAnalyzer(str(tmp_path))
        assert "Dependabot:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = DependabotAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "version: 2" in template
        assert "security-updates" in template

    def test_finding_format(self):
        finding = DependabotFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="dependabot.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
