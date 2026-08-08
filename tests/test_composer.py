"""Tests for ProgramComposer."""

import pytest

from devai import DevRuntime
from devai.composer import ProgramComposer


class TestProgramComposer:
    def test_build_review_security(self):
        runtime = DevRuntime.create(use_mock=True)
        program = (
            runtime.composer("audit")
            .review("check")
            .security("audit")
            .build()
        )
        assert program.name == "audit"
        assert len(program.tasks) == 2
        assert program.tasks[0].action == "review"
        assert program.tasks[1].action == "security"

    def test_chain_returns_self(self):
        runtime = DevRuntime.create(use_mock=True)
        composer = runtime.composer()
        assert composer.review() is composer
        assert composer.explain() is composer

    def test_run_built_program(self):
        runtime = DevRuntime.create(use_mock=True)
        program = runtime.composer("quick").review().build()
        results = program.run({"code": "def foo(): pass"})
        assert len(results) == 1
        assert results[0].action == "review"

    def test_save_json(self, tmp_path):
        runtime = DevRuntime.create(use_mock=True)
        path = tmp_path / "program.json"
        runtime.composer("saved").review().save(path)
        assert path.exists()
        loaded = runtime.load_program(path)
        assert loaded.name == "saved"
        assert len(loaded.tasks) == 1

    def test_from_program(self):
        runtime = DevRuntime.create(use_mock=True)
        original = runtime.composer("orig").review().build()
        edited = ProgramComposer.from_program(original).security().build()
        assert len(edited.tasks) == 2

    def test_invalid_action_raises(self):
        runtime = DevRuntime.create(use_mock=True)
        with pytest.raises(ValueError, match="Unsupported action"):
            runtime.composer().step("bad", "not_real")

    def test_empty_build_raises(self):
        runtime = DevRuntime.create(use_mock=True)
        with pytest.raises(ValueError, match="Invalid program"):
            runtime.composer().build()
