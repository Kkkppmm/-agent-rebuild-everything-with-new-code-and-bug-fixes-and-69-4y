"""Tests for DevAI presets."""

import pytest

from devai import CodeAssistant, DevProgram, get_preset, list_presets
from devai.core import MockLLMClient


class TestPresets:
    def test_list_presets(self):
        presets = list_presets()
        assert len(presets) >= 8
        names = {p["name"] for p in presets}
        assert "pre-commit" in names
        assert "release" in names
        assert "ci-gate" in names

    def test_get_preset(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="ok"))
        program = get_preset("pre-commit", assistant)
        assert isinstance(program, DevProgram)
        assert program.name == "pre-commit"
        assert len(program.tasks) == 3

    def test_get_preset_aliases(self):
        assistant = CodeAssistant(client=MockLLMClient())
        program = get_preset("pre_commit", assistant)
        assert program.name == "pre-commit"

    def test_unknown_preset(self):
        assistant = CodeAssistant(client=MockLLMClient())
        with pytest.raises(ValueError, match="Unknown preset"):
            get_preset("not-a-preset", assistant)

    def test_preset_runs(self):
        client = MockLLMClient(default_response="done")
        assistant = CodeAssistant(client=client)
        program = get_preset("onboarding", assistant)
        results = program.run({"code": "def foo(): pass"})
        assert len(results) == 3
        assert results[0].action == "explain"

    def test_test_gen_preset(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="ok"))
        program = get_preset("test-gen", assistant)
        assert program.name == "test-gen"
        assert len(program.tasks) == 3
        results = program.run({"code": "def add(a, b): return a + b"})
        assert results[-1].action == "tests"

    def test_hotfix_preset(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="ok"))
        program = get_preset("hotfix", assistant)
        assert program.name == "hotfix"
        assert len(program.tasks) == 3
        assert program.is_valid()
