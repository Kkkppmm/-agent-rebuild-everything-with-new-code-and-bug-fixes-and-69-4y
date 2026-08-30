"""Tests for plugin registry."""

import pytest

from devai import CodeAssistant, PluginRegistry
from devai.core import MockLLMClient
from devai.plugins import register_builtin_plugins


class TestPluginRegistry:
    def test_register_and_call(self):
        registry = PluginRegistry()
        registry.register("greet", lambda name: f"hi {name}")
        assert registry.call("greet", "dev") == "hi dev"

    def test_names(self):
        registry = PluginRegistry()
        registry.register("a", lambda: "a")
        registry.register("b", lambda: "b")
        assert registry.names() == ["a", "b"]

    def test_unknown_action(self):
        registry = PluginRegistry()
        with pytest.raises(KeyError):
            registry.call("missing")

    def test_invalid_name(self):
        registry = PluginRegistry()
        with pytest.raises(ValueError):
            registry.register("bad name!", lambda: "")

    def test_extend_program_actions(self):
        registry = PluginRegistry()
        registry.register("custom", lambda: "x")
        extended = registry.extend_program_actions(frozenset({"review"}))
        assert "custom" in extended
        assert "review" in extended

    def test_register_builtin_plugins(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="ok"))
        registry = PluginRegistry()
        register_builtin_plugins(registry, assistant)
        assert "review" in registry.names()
        assert registry.call("review", "code") == "ok"
