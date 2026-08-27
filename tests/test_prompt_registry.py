"""Tests for PromptRegistry."""

import pytest

from devai import PromptRegistry
from devai.prompts import PromptTemplate


class TestPromptRegistry:
    def test_builtins_loaded(self):
        registry = PromptRegistry()
        assert "code_review" in registry
        assert "debug" in registry.list()

    def test_register_and_get(self):
        registry = PromptRegistry(include_builtins=False)
        template = PromptTemplate(
            template="Hello $name",
            input_variables=["name"],
        )
        registry.register("greet", template)
        assert registry.get("greet").format(name="world") == "Hello world"

    def test_register_duplicate_raises(self):
        registry = PromptRegistry(include_builtins=False)
        template = PromptTemplate(template="x", input_variables=[])
        registry.register("test", template)
        with pytest.raises(ValueError, match="already registered"):
            registry.register("test", template)

    def test_register_overwrite(self):
        registry = PromptRegistry(include_builtins=False)
        t1 = PromptTemplate(template="a", input_variables=[])
        t2 = PromptTemplate(template="b", input_variables=[])
        registry.register("test", t1)
        registry.register("test", t2, overwrite=True)
        assert registry.get("test").template == "b"

    def test_get_unknown_raises(self):
        registry = PromptRegistry(include_builtins=False)
        with pytest.raises(KeyError):
            registry.get("missing")

    def test_unregister(self):
        registry = PromptRegistry(include_builtins=False)
        template = PromptTemplate(template="x", input_variables=[])
        registry.register("temp", template)
        registry.unregister("temp")
        assert "temp" not in registry

    def test_list_sorted(self):
        registry = PromptRegistry(include_builtins=False)
        registry.register("zebra", PromptTemplate(template="z", input_variables=[]))
        registry.register("alpha", PromptTemplate(template="a", input_variables=[]))
        assert registry.list() == ["alpha", "zebra"]

    def test_facade_prompts(self):
        from devai import DevAI

        registry = DevAI.prompts()
        assert isinstance(registry, PromptRegistry)
        assert len(registry.list()) > 10
