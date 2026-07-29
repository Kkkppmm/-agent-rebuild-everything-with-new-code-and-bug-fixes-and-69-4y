"""Tests for environment diagnostics and report export."""

import json
from pathlib import Path

import pytest

from devai import DevDoctor, DoctorResult, ProgramReport, run_doctor
from devai.core import MockLLMClient
from devai.program import ProgramResult
from devai.runtime import DevRuntime


class TestDevDoctor:
    def test_run_mock_mode(self):
        doctor = DevDoctor(use_mock=True, check_provider=True)
        result = doctor.run()
        assert isinstance(result, DoctorResult)
        assert result.healthy is True
        names = {check.name for check in result.checks}
        assert "python" in names
        assert "devai" in names
        assert "api_key" in names

    def test_run_doctor_helper(self):
        result = run_doctor(use_mock=True)
        assert result.healthy is True

    def test_summary(self):
        result = run_doctor(use_mock=True)
        summary = result.summary()
        assert "DevAI doctor" in summary
        assert "PASS" in summary

    def test_to_dict(self):
        result = run_doctor(use_mock=True)
        data = result.to_dict()
        assert data["healthy"] is True
        assert len(data["checks"]) >= 5

    def test_missing_api_key_fails(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("DEVAI_API_KEY", raising=False)
        doctor = DevDoctor(check_provider=False)
        result = doctor.run()
        api_check = next(c for c in result.checks if c.name == "api_key")
        assert api_check.passed is False


class TestProgramReport:
    def test_from_program(self):
        results = [
            ProgramResult(name="review", action="review", output="Looks good"),
            ProgramResult(name="security", action="security", output="No issues"),
        ]
        report = ProgramReport.from_program("pre-commit", results, context={"code": "x = 1"})
        assert report.name == "pre-commit"
        md = report.to_markdown()
        assert "Looks good" in md
        assert "x = 1" in md

    def test_to_json(self):
        results = [ProgramResult(name="step", action="review", output="ok")]
        report = ProgramReport.from_program("test", results)
        data = json.loads(report.to_json())
        assert data["type"] == "program"
        assert data["tasks"][0]["output"] == "ok"

    def test_save_json_and_markdown(self, tmp_path: Path):
        results = [ProgramResult(name="step", action="review", output="ok")]
        report = ProgramReport.from_program("test", results)
        json_path = tmp_path / "report.json"
        md_path = tmp_path / "report.md"
        report.save(json_path)
        report.save(md_path)
        assert json.loads(json_path.read_text())["name"] == "test"
        assert "# DevAI Report" in md_path.read_text()

    def test_from_workflow(self):
        runtime = DevRuntime.create(use_mock=True)
        workflow = runtime.workflow("demo")
        workflow.add("review", "pre-commit")
        wf_result = runtime.run_workflow(workflow, {"code": "def foo(): pass"})
        report = ProgramReport.from_workflow(wf_result)
        assert report.workflow is not None
        assert "demo" in report.to_markdown()

    def test_runtime_report_helper(self):
        runtime = DevRuntime.create(use_mock=True)
        results = runtime.run("pre-commit", {"code": "x = 1"})
        report = runtime.report(results, name="pre-commit")
        assert isinstance(report, ProgramReport)
        assert report.to_json()
