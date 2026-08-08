"""Tests for WorkflowAnalyzer."""

from pathlib import Path

from devai.workflow_analyzer import WorkflowAnalyzer, WorkflowFinding


INSECURE_WORKFLOW = """
name: CI
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - name: Install
        run: curl -fsSL https://example.com/install.sh | bash
        env:
          API_TOKEN: sk-live-hardcoded-secret
"""

HARDENED_WORKFLOW = """
name: CI
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be708477a393ebcf08
      - run: pip install -e ".[dev]"
      - run: pytest
"""


class TestWorkflowAnalyzer:
    def test_no_workflows_returns_perfect_score(self, tmp_path: Path):
        analyzer = WorkflowAnalyzer(str(tmp_path))
        assert analyzer.stats.workflows == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(INSECURE_WORKFLOW, encoding="utf-8")
        analyzer = WorkflowAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "floating_action_ref" in kinds or "unpinned_action" in kinds
        assert "curl_pipe_shell" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 60.0

    def test_hardened_workflow_scores_well(self, tmp_path: Path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(HARDENED_WORKFLOW, encoding="utf-8")
        analyzer = WorkflowAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(HARDENED_WORKFLOW, encoding="utf-8")
        analyzer = WorkflowAnalyzer(str(tmp_path))
        assert "Workflows:" in analyzer.summary()
        assert "GitHub Actions" in analyzer.to_context()

    def test_finding_format(self):
        finding = WorkflowFinding(
            kind="unpinned_action",
            severity="medium",
            message="not pinned",
            path=".github/workflows/ci.yml",
            lineno=10,
        )
        assert "ci.yml:10" in finding.format()
