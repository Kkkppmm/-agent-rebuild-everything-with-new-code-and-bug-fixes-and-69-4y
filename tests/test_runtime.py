"""Tests for DevRuntime."""

from pathlib import Path

import pytest

from devai import DevAIConfig, DevRuntime, MockLLMClient
from devai.core.exceptions import ConfigError


class TestDevAIConfigProviders:
    def test_for_openai(self):
        config = DevAIConfig.for_openai(api_key="sk-test", model="gpt-4o")
        assert config.api_key == "sk-test"
        assert config.model == "gpt-4o"
        assert config.base_url == "https://api.openai.com/v1"

    def test_for_ollama(self):
        config = DevAIConfig.for_ollama(model="codellama")
        assert config.api_key == "ollama"
        assert config.model == "codellama"
        assert "11434" in config.base_url

    def test_from_provider_openai(self):
        config = DevAIConfig.from_provider("openai", api_key="key")
        assert config.base_url.endswith("/v1")

    def test_from_provider_ollama(self):
        config = DevAIConfig.from_provider("ollama")
        assert config.api_key == "ollama"

    def test_from_provider_mock(self):
        config = DevAIConfig.from_provider("mock")
        assert config.api_key == "mock"

    def test_from_provider_unknown(self):
        try:
            DevAIConfig.from_provider("unknown")
            assert False, "expected ConfigError"
        except ConfigError:
            pass


class TestDevRuntime:
    def test_create_mock(self):
        runtime = DevRuntime.create(use_mock=True)
        assert runtime.assistant is not None
        assert runtime.kit is not None
        result = runtime.review("def foo(): pass")
        assert isinstance(result, str)

    def test_create_mock_provider(self):
        runtime = DevRuntime.create(provider="mock")
        assert runtime.config.api_key == "mock"

    def test_from_config(self):
        config = DevAIConfig(api_key="mock", model="test")
        runtime = DevRuntime.from_config(config, client=MockLLMClient())
        assert runtime.config.model == "test"

    def test_program_and_run(self):
        runtime = DevRuntime.create(use_mock=True)
        program = runtime.program("audit").add("review", "review")
        results = runtime.run(program, {"code": "x = 1"})
        assert len(results) == 1
        assert results[0].action == "review"

    def test_preset_run(self):
        runtime = DevRuntime.create(use_mock=True)
        results = runtime.run("pre-commit", {"code": "def foo(): pass"})
        assert len(results) == 3

    def test_load_program_file(self, tmp_path: Path):
        program_file = tmp_path / "test.json"
        program_file.write_text(
            '{"name": "quick", "tasks": [{"name": "review", "action": "review"}]}'
        )
        runtime = DevRuntime.create(use_mock=True)
        results = runtime.run(str(program_file), {"code": "pass"})
        assert len(results) == 1

    def test_summarize(self):
        runtime = DevRuntime.create(use_mock=True)
        results = runtime.run("pre-commit", {"code": "def foo(): pass"})
        summary = runtime.summarize(results)
        assert "## review" in summary

    def test_explain_and_generate(self):
        runtime = DevRuntime.create(use_mock=True)
        assert isinstance(runtime.explain("x = 1"), str)
        assert isinstance(runtime.generate("a fibonacci function"), str)

    def test_dry_run(self):
        runtime = DevRuntime.create(use_mock=True)
        plan = runtime.dry_run("pre-commit", {"code": "def foo(): pass"})
        assert len(plan) == 3
        assert plan[0].action == "review"

    @pytest.mark.asyncio
    async def test_arun(self):
        runtime = DevRuntime.create(use_mock=True)
        results = await runtime.arun("hotfix", {"code": "def foo(): pass"})
        assert len(results) == 3
        assert results[1].action == "security"

    def test_workflow(self):
        runtime = DevRuntime.create(use_mock=True)
        workflow = runtime.workflow("test").add("step", "hotfix")
        result = runtime.run_workflow(workflow, {"code": "x = 1"})
        assert len(result.steps) == 1
        assert result.steps[0].name == "step"

    @pytest.mark.asyncio
    async def test_arun_workflow(self):
        runtime = DevRuntime.create(use_mock=True)
        workflow = runtime.workflow("async").add("step", "hotfix")
        result = await runtime.arun_workflow(workflow, {"code": "x = 1"})
        assert len(result.steps) == 1

    def test_run_inline_dict(self):
        runtime = DevRuntime.create(use_mock=True)
        program = {"name": "inline", "tasks": [{"name": "review", "action": "review"}]}
        results = runtime.run_inline(program, {"code": "def foo(): pass"})
        assert len(results) == 1
        assert results[0].action == "review"

    def test_run_inline_json_text(self):
        runtime = DevRuntime.create(use_mock=True)
        text = '{"name": "inline-json", "tasks": [{"name": "review", "action": "review"}]}'
        results = runtime.run_inline(text, {"code": "pass"})
        assert len(results) == 1

    def test_dry_run_inline(self):
        runtime = DevRuntime.create(use_mock=True)
        program = {"tasks": [{"name": "review", "action": "review"}]}
        plan = runtime.dry_run_inline(program, {"code": "x = 1"})
        assert len(plan) == 1
        assert plan[0].action == "review"

    def test_context_from_file(self, tmp_path: Path):
        source = tmp_path / "module.py"
        source.write_text("def add(a, b): return a + b", encoding="utf-8")
        context = DevRuntime.context_from_file(source)
        assert "add" in context["code"]

    def test_run_on_file_preset(self, tmp_path: Path):
        source = tmp_path / "app.py"
        source.write_text("def foo(): pass", encoding="utf-8")
        runtime = DevRuntime.create(use_mock=True)
        results = runtime.run_on_file("pre-commit", source)
        assert len(results) == 3

    def test_run_on_file_inline(self, tmp_path: Path):
        source = tmp_path / "lib.py"
        source.write_text("x = 1", encoding="utf-8")
        runtime = DevRuntime.create(use_mock=True)
        inline = {"tasks": [{"name": "review", "action": "review"}]}
        results = runtime.run_on_file(inline, source)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_arun_on_file(self, tmp_path: Path):
        source = tmp_path / "async.py"
        source.write_text("async def foo(): pass", encoding="utf-8")
        runtime = DevRuntime.create(use_mock=True)
        inline = {"tasks": [{"name": "review", "action": "review"}]}
        results = await runtime.arun_on_file(inline, source)
        assert len(results) == 1

    def test_quick_action(self):
        runtime = DevRuntime.create(use_mock=True)
        output = runtime.quick_action("review", "def bar(): pass")
        assert isinstance(output, str)
