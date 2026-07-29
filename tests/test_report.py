"""Tests for DevAI program and workflow reports."""

import json
from pathlib import Path

from devai.program import ProgramResult
from devai.report import ProgramReport
from devai.workflow import WorkflowResult, WorkflowStepResult


def _sample_results() -> list[ProgramResult]:
    return [
        ProgramResult(name="review", action="review", output="Looks good."),
        ProgramResult(name="security", action="security", output="No issues."),
    ]


def _sample_workflow() -> WorkflowResult:
    return WorkflowResult(
        name="ci",
        steps=[
            WorkflowStepResult(
                name="review",
                program_name="pre-commit",
                results=_sample_results()[:1],
                duration_seconds=0.5,
            )
        ],
        context={"code": "def foo(): pass"},
        duration_seconds=0.5,
    )


class TestProgramReport:
    def test_from_program(self):
        report = ProgramReport.from_program(_sample_results(), title="Test Report")
        assert report.title == "Test Report"
        assert report.results is not None
        assert len(report.results) == 2

    def test_from_workflow(self):
        report = ProgramReport.from_workflow(_sample_workflow())
        assert report.workflow is not None
        assert report.workflow.name == "ci"

    def test_to_dict_program(self):
        report = ProgramReport.from_program(_sample_results())
        data = report.to_dict()
        assert data["type"] == "program"
        assert len(data["results"]) == 2
        assert data["results"][0]["action"] == "review"

    def test_to_dict_workflow(self):
        report = ProgramReport.from_workflow(_sample_workflow())
        data = report.to_dict()
        assert data["type"] == "workflow"
        assert data["workflow"]["name"] == "ci"

    def test_to_json(self):
        report = ProgramReport.from_program(_sample_results())
        payload = json.loads(report.to_json())
        assert payload["type"] == "program"

    def test_to_markdown(self):
        report = ProgramReport.from_program(_sample_results(), author="test")
        md = report.to_markdown()
        assert "# Test Report" in md or "# DevAI Program Report" in md
        assert "review" in md
        assert "author" in md

    def test_save_json(self, tmp_path: Path):
        report = ProgramReport.from_program(_sample_results())
        path = report.save(tmp_path / "report.json")
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["type"] == "program"

    def test_save_markdown(self, tmp_path: Path):
        report = ProgramReport.from_program(_sample_results())
        path = report.save(tmp_path / "report.md")
        assert path.exists()
        assert "review" in path.read_text()

    def test_workflow_markdown(self):
        report = ProgramReport.from_workflow(_sample_workflow())
        md = report.to_markdown()
        assert "Workflow: ci" in md
