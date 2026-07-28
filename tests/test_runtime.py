"""Tests for DevRuntime."""

from pathlib import Path

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
