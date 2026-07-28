"""Tests for DevKit."""

from pathlib import Path

import pytest

from devai import CodeAssistant, DevKit, MockLLMClient


class TestDevKit:
    def test_from_client(self):
        kit = DevKit.from_client(MockLLMClient())
        assert isinstance(kit.assistant, CodeAssistant)

    def test_presets(self):
        kit = DevKit.from_client(MockLLMClient())
        presets = kit.presets()
        assert any(p["name"] == "release" for p in presets)

    def test_preset_program(self):
        kit = DevKit.from_client(MockLLMClient(default_response="ok"))
        program = kit.preset("pre-commit")
        assert program.name == "pre-commit"

    def test_audit(self):
        kit = DevKit.from_client(MockLLMClient(default_response="audited"))
        result = kit.audit("def foo(): pass")
        assert "audited" in result

    def test_pre_commit(self):
        kit = DevKit.from_client(MockLLMClient(default_response="checked"))
        result = kit.pre_commit("x = 1")
        assert "checked" in result

    def test_onboard(self):
        kit = DevKit.from_client(MockLLMClient(default_response="explained"))
        result = kit.onboard("class Foo: pass")
        assert "explained" in result

    def test_release_check(self):
        kit = DevKit.from_client(MockLLMClient(default_response="ready"))
        result = kit.release_check("def bar(): return 1")
        assert "ready" in result

    def test_run_program_by_name(self):
        kit = DevKit.from_client(MockLLMClient(default_response="done"))
        results = kit.run_program("onboarding", {"code": "pass"})
        assert len(results) == 3

    def test_summarize(self):
        from devai.program import ProgramResult

        kit = DevKit.from_client(MockLLMClient())
        summary = kit.summarize(
            [ProgramResult(name="step", action="review", output="output text")]
        )
        assert "step" in summary
        assert "output text" in summary

    def test_read_code_from_file(self, tmp_path: Path):
        code_file = tmp_path / "sample.py"
        code_file.write_text("def sample(): pass")
        kit = DevKit.from_client(MockLLMClient(default_response="file ok"))
        result = kit.audit(str(code_file))
        assert "file ok" in result

    def test_review_project_requires_path(self):
        kit = DevKit.from_client(MockLLMClient())
        with pytest.raises(ValueError, match="project_path"):
            kit.review_project()

    def test_review_project(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def main(): pass")
        kit = DevKit.from_client(
            MockLLMClient(default_response="project reviewed"),
            project_path=tmp_path,
        )
        result = kit.review_project()
        assert "project reviewed" in result

    def test_pipeline(self):
        kit = DevKit.from_client(MockLLMClient())
        pipeline = kit.pipeline()
        assert pipeline.assistant is kit.assistant

    def test_program_builder(self):
        kit = DevKit.from_client(MockLLMClient())
        program = kit.program("custom").add("review", "review")
        assert program.name == "custom"
        assert len(program.tasks) == 1

    def test_ci_gate(self):
        kit = DevKit.from_client(MockLLMClient(default_response="gate ok"))
        result = kit.ci_gate(diff="diff --git a/x.py", code="x = 1")
        assert "gate ok" in result
