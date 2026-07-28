"""Tests for YAML program loading."""

import pytest

from devai import CodeAssistant, DevProgram, MockLLMClient


class TestYAMLPrograms:
    def test_from_yaml(self):
        yaml_text = """
name: yaml-test
tasks:
  - name: review
    action: review
"""
        assistant = CodeAssistant(client=MockLLMClient(default_response="ok"))
        program = DevProgram.from_yaml(yaml_text, assistant)
        assert program.name == "yaml-test"
        assert len(program.tasks) == 1

    def test_from_yaml_file(self, tmp_path):
        program_file = tmp_path / "audit.yaml"
        program_file.write_text(
            "name: file-test\n"
            "tasks:\n"
            "  - name: explain\n"
            "    action: explain\n"
        )
        assistant = CodeAssistant(client=MockLLMClient(default_response="explained"))
        program = DevProgram.from_file(program_file, assistant)
        assert program.name == "file-test"
        results = program.run({"code": "def foo(): pass"})
        assert results[0].output == "explained"

    def test_from_yaml_import_error(self):
        import builtins
        import sys

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("no yaml")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = mock_import
        try:
            assistant = CodeAssistant(client=MockLLMClient())
            with pytest.raises(ImportError, match="PyYAML"):
                DevProgram.from_yaml("name: test\n", assistant)
        finally:
            builtins.__import__ = real_import
