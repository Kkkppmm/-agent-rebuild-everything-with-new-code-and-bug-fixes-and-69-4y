"""Tests for WorkflowAnalyzer."""

from pathlib import Path

from devai.workflow_analyzer import WorkflowAnalyzer


INSECURE_WORKFLOW = """
name: CI
on:
  pull_request_target:
    branches: [main]
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: curl https://example.com/install.sh | bash
        env:
          API_SECRET: hardcoded-secret
"""

HARDENED_WORKFLOW = """
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pytest
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
        assert "pull_request_target" in kinds
        assert "unpinned_action" in kinds
        assert "curl_pipe_shell" in kinds
        assert "secret_in_env" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_workflow_scores_well(self, tmp_path: Path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(HARDENED_WORKFLOW, encoding="utf-8")
        analyzer = WorkflowAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.workflows == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(HARDENED_WORKFLOW, encoding="utf-8")
        analyzer = WorkflowAnalyzer(str(tmp_path))
        assert "Workflows:" in analyzer.summary()
        assert "Workflow analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "permissions:" in template
        assert "actions/checkout@v4" in template
