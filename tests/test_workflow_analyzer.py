"""Tests for WorkflowAnalyzer."""

from pathlib import Path

from devai.workflow_analyzer import WorkflowAnalyzer, WorkflowFinding

INSECURE_WORKFLOW = """
name: CI
on:
  pull_request_target:
    branches: [main]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      API_SECRET: supersecret
    steps:
      - uses: actions/checkout@main
      - run: curl -fsSL https://example.com/install.sh | bash
      - run: echo "${{ github.event.issue.title }}"
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
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
      - uses: actions/setup-python@8d9f9acfe6e514bcd561bc4b96759fba508e4aeb
        with:
          python-version: "3.12"
      - run: python -m pytest
"""


class TestWorkflowAnalyzer:
    def test_no_workflows_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
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
        assert "write_all_permissions" in kinds
        assert "secret_in_env" in kinds
        assert "unpinned_action" in kinds
        assert "curl_pipe_shell" in kinds
        assert "script_injection" in kinds
        assert "checkout_with_pr_target" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_workflow_scores_well(self, tmp_path: Path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(HARDENED_WORKFLOW, encoding="utf-8")
        analyzer = WorkflowAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.workflows == 1
        assert analyzer.infos[0].uses_checkout is True

    def test_detects_mutable_tag(self, tmp_path: Path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "deploy.yml").write_text(
            "on: push\njobs:\n  deploy:\n    steps:\n      - uses: actions/checkout@v4\n",
            encoding="utf-8",
        )
        analyzer = WorkflowAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "mutable_tag" for f in findings)

    def test_summary_context_and_template(self, tmp_path: Path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(HARDENED_WORKFLOW, encoding="utf-8")
        analyzer = WorkflowAnalyzer(str(tmp_path))
        assert "Workflows:" in analyzer.summary()
        assert "workflow analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "persist-credentials: false" in template
        assert "permissions:" in template

    def test_finding_format(self):
        finding = WorkflowFinding(
            kind="unpinned_action",
            severity="high",
            message="test message",
            path=".github/workflows/ci.yml",
            lineno=10,
            line="uses: actions/checkout@main",
        )
        assert "[high]" in finding.format()
        assert "ci.yml:10" in finding.format()
