"""Tests for DevApp."""

import json
from pathlib import Path

from devai import DevApp, DevRuntime


class TestDevApp:
    def test_create_mock(self):
        app = DevApp.create(name="test-app", use_mock=True)
        assert app.name == "test-app"
        assert app.runtime is not None

    def test_from_runtime(self):
        runtime = DevRuntime.create(use_mock=True)
        app = DevApp.from_runtime(runtime, name="wrapped")
        assert app.runtime is runtime

    def test_use_preset_and_run(self):
        app = DevApp.create(use_mock=True).use_preset("pre-commit")
        results = app.run(context={"code": "def foo(): pass"})
        assert len(results) == 3

    def test_with_context(self):
        app = (
            DevApp.create(use_mock=True)
            .use_preset("pre-commit")
            .with_context(code="def bar(): pass")
        )
        results = app.run()
        assert len(results) == 3

    def test_load_program(self, tmp_path: Path):
        program_file = tmp_path / "quick.json"
        program_file.write_text(
            json.dumps(
                {
                    "name": "quick",
                    "tasks": [{"name": "review", "action": "review"}],
                }
            )
        )
        app = DevApp.create(use_mock=True)
        app.load(program_file)
        results = app.run(context={"code": "x = 1"})
        assert len(results) == 1

    def test_summarize(self):
        app = DevApp.create(use_mock=True).use_preset("pre-commit")
        results = app.run(context={"code": "pass"})
        summary = app.summarize(results)
        assert "## review" in summary

    def test_cli_dry_run(self, capsys):
        app = DevApp.create(use_mock=True, default_program="pre-commit")
        exit_code = app.cli(["--dry-run", "--code", "def foo(): pass"])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "review" in captured.out

    def test_cli_run(self, capsys):
        app = DevApp.create(use_mock=True, default_program="pre-commit")
        exit_code = app.cli(["--code", "def foo(): pass"])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "## review" in captured.out

    def test_run_without_program_raises(self):
        app = DevApp.create(use_mock=True)
        try:
            app.run()
            assert False, "expected ValueError"
        except ValueError:
            pass
