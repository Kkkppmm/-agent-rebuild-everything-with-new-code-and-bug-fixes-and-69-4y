"""Tests for DevApp application framework."""

from devai import DevApp, CodeAssistant
from devai.core import MockLLMClient


class TestDevApp:
    def test_create_with_mock(self):
        app = DevApp.create(name="testapp", use_mock=True)
        assert app.name == "testapp"
        assert app.runtime is not None
        assert app.assistant is not None

    def test_register_command(self):
        app = DevApp.create(name="testapp", use_mock=True)

        @app.command("greet", help="Say hello")
        def greet() -> str:
            return "hello"

        assert "greet" in app.commands
        assert app.commands["greet"].help == "Say hello"

    def test_register_preset(self):
        app = DevApp.create(name="testapp", use_mock=True)
        program = app.register_preset("pre-commit")
        assert program.name == "pre-commit"
        assert "pre-commit" in app._programs

    def test_run_program(self):
        client = MockLLMClient(default_response="ok")
        assistant = CodeAssistant(client=client)
        app = DevApp(name="testapp", runtime=None)
        from devai import DevProgram

        program = DevProgram("simple", assistant).add("review", "review")
        app.register_program("simple", program)
        results = app.run_program("simple", {"code": "x = 1"})
        assert len(results) == 1
        assert results[0].action == "review"

    def test_run_preset_via_runtime(self):
        app = DevApp.create(name="testapp", use_mock=True)
        results = app.run_program("onboarding", {"code": "def foo(): pass"})
        assert len(results) == 3
