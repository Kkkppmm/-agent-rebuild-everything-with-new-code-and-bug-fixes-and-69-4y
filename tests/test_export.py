"""Tests for program export."""

import subprocess
import sys

from devai import CodeAssistant, DevProgram, export_program, export_program_to_file
from devai.core import MockLLMClient


class TestExportProgram:
    def test_export_generates_script(self):
        assistant = CodeAssistant(client=MockLLMClient())
        program = DevProgram("demo", assistant).add("review", "review")
        script = export_program(program, use_mock=True)

        assert "#!/usr/bin/env python3" in script
        assert "demo" in script
        assert "DevRuntime" in script
        assert "PROGRAM = json.loads" in script

    def test_export_to_file_and_run(self, tmp_path):
        assistant = CodeAssistant(client=MockLLMClient(default_response="Reviewed"))
        program = DevProgram("export-test", assistant).add("review", "review")
        script_path = tmp_path / "run_program.py"
        export_program_to_file(program, script_path, use_mock=True)

        assert script_path.exists()
        assert script_path.stat().st_mode & 0o111

        result = subprocess.run(
            [sys.executable, str(script_path), "def foo(): pass"],
            capture_output=True,
            text=True,
            cwd=tmp_path,
            env={**__import__("os").environ, "PYTHONPATH": str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src")},
        )
        assert result.returncode == 0
        assert "Reviewed" in result.stdout or "review" in result.stdout.lower()

    def test_export_json_output_flag(self, tmp_path):
        assistant = CodeAssistant(client=MockLLMClient(default_response="ok"))
        program = DevProgram("json-export", assistant).add("review", "review")
        script_path = tmp_path / "run_json.py"
        export_program_to_file(program, script_path, use_mock=True)

        result = subprocess.run(
            [sys.executable, str(script_path), "x=1", "--json"],
            capture_output=True,
            text=True,
            env={**__import__("os").environ, "PYTHONPATH": str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src")},
        )
        assert result.returncode == 0
        assert '"name": "review"' in result.stdout
