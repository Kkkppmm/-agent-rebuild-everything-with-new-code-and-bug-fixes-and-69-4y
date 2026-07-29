"""Tests for ProgramReport export."""

import json
from pathlib import Path

from devai import ProgramReport, quickstart
from devai.program import ProgramResult
from devai.workflow import DevWorkflow, WorkflowResult, WorkflowStepResult


class TestProgramReport:
    def test_from_results_to_json(self):
        results = [
            ProgramResult(name="review", action="review", output="Looks good"),
            ProgramResult(name="security", action="security", output="No issues"),
        ]
        report = ProgramReport.from_results("pre-commit", results)
        data = json.loads(report.to_json())
        assert data["name"] == "pre-commit"
        assert data["type"] == "program"
        assert len(data["results"]) == 2

    def test_from_results_to_markdown(self):
        results = [ProgramResult(name="review", action="review", output="OK")]
        report = ProgramReport.from_results("test", results)
        md = report.to_markdown()
        assert "# Program: test" in md
        assert "## review" in md
        assert "OK" in md

    def test_from_workflow(self):
        wf = WorkflowResult(
            name="ci",
            steps=[
                WorkflowStepResult(
                    name="lint",
                    program_name="pre-commit",
                    results=[ProgramResult(name="review", action="review", output="pass")],
                    duration_seconds=0.1,
                )
            ],
            context={},
            duration_seconds=0.1,
        )
        report = ProgramReport.from_workflow(wf)
        data = report.to_dict()
        assert data["type"] == "workflow"
        assert data["steps"][0]["name"] == "lint"

    def test_save_json_and_markdown(self, tmp_path: Path):
        results = [ProgramResult(name="a", action="review", output="x")]
        report = ProgramReport.from_results("demo", results)
        json_path = tmp_path / "out.json"
        md_path = tmp_path / "out.md"
        report.save(json_path)
        report.save(md_path)
        assert json.loads(json_path.read_text())["name"] == "demo"
        assert "# Program: demo" in md_path.read_text()

    def test_integration_runtime(self):
        runtime = quickstart(use_mock=True)
        results = runtime.run("pre-commit", {"code": "def foo(): pass"})
        report = ProgramReport.from_results("pre-commit", results)
        assert report.to_dict()["type"] == "program"
        assert len(report.results) >= 1

    def test_integration_workflow(self):
        runtime = quickstart(use_mock=True)
        workflow = DevWorkflow("demo", runtime.assistant)
        workflow.add("review", "pre-commit")
        wf_result = workflow.run({"code": "x = 1"})
        report = ProgramReport.from_workflow(wf_result)
        assert "Workflow: demo" in report.to_markdown()
