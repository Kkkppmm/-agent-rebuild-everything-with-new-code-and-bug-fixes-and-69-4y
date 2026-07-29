"""Tests for program reporting."""

import json

from devai import DevRuntime, ProgramReport


class TestProgramReport:
    def test_from_program(self):
        runtime = DevRuntime.create(use_mock=True)
        results = runtime.run("pre-commit", {"code": "x = 1"})
        report = ProgramReport.from_program("pre-commit", results)
        md = report.to_markdown()
        assert "pre-commit" in md or "review" in md
        data = json.loads(report.to_json())
        assert data["type"] == "program"
        assert len(data["tasks"]) == 3

    def test_save_markdown(self, tmp_path):
        runtime = DevRuntime.create(use_mock=True)
        results = runtime.run("pre-commit", {"code": "pass"})
        report = ProgramReport.from_program("test", results)
        path = tmp_path / "report.md"
        report.save(path)
        assert path.read_text()
