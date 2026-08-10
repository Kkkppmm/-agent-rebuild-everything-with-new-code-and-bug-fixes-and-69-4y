"""Tests for optional OpenAI SDK adapter."""

import pytest

from devai.core.config import DevAIConfig


class TestOpenAIAdapter:
    def test_requires_openai_package(self):
        pytest.importorskip("openai")
        from devai.core.openai_adapter import OpenAIAdapter

        adapter = OpenAIAdapter(DevAIConfig(api_key="test-key"))
        assert adapter.config.api_key == "test-key"

    def test_import_error_message(self):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "openai":
                raise ImportError("No module named 'openai'")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = fake_import
        try:
            import importlib

            module = importlib.import_module("devai.core.openai_adapter")
            importlib.reload(module)
            with pytest.raises(ImportError, match="devai\\[openai\\]"):
                module.OpenAIAdapter(DevAIConfig(api_key="test"))
        finally:
            builtins.__import__ = real_import
