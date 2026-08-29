"""Tests for program and workflow report export."""

import json

from devai import ProgramReport, ProgramResult, quickstart
from devai.workflow import DevWorkflow


class TestProgramReport:
    def test_from_program_results(self):
        results = [
            ProgramResult(name="review", action="review", output="Looks good"),
            ProgramResult(name="security", action="security", output="No issues"),
        ]
        report = ProgramReport.from_program_results(
            results, title="Test Report", program_name="pre-commit"
        )
        assert report.title == "Test Report"
        assert report.source == "pre-commit"

    def test_to_json(self):
        results = [ProgramResult(name="step", action="review", output="ok")]
        report = ProgramReport.from_program_results(results)
        data = json.loads(report.to_json())
        assert data["results"][0]["name"] == "step"

    def test_to_markdown(self):
        results = [ProgramResult(name="step", action="review", output="ok")]
        report = ProgramReport.from_program_results(results)
        md = report.to_markdown()
        assert "# " in md
        assert "step" in md

    def test_step_summaries(self):
        results = [ProgramResult(name="step", action="review", output="hello")]
        report = ProgramReport.from_program_results(results)
        summaries = report.step_summaries()
        assert summaries[0]["output_length"] == 5

    def test_from_workflow(self):
        runtime = quickstart(use_mock=True)
        workflow = DevWorkflow(name="test-wf", assistant=runtime.assistant)
        workflow.add("review", "pre-commit")
        result = workflow.run({"code": "x = 1"})
        report = ProgramReport.from_workflow(result)
        assert "test-wf" in report.title
        md = report.to_markdown()
        assert "Workflow Steps" in md

    def test_runtime_report(self):
        runtime = quickstart(use_mock=True)
        results = runtime.run("pre-commit", {"code": "def foo(): pass"})
        md = runtime.report(results, title="pre-commit")
        assert "pre-commit" in md
        json_out = runtime.report(results, format="json")
        data = json.loads(json_out)
        assert "results" in data
