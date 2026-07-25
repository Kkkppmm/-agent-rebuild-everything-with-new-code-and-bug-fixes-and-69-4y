"""Tests for tool registry."""


from devai.tools import ToolRegistry, function_to_tool
from devai.types import ToolCall


def sample_fn(x: int, label: str = "test") -> str:
    """Add numbers and return a label."""
    return f"{label}:{x}"


def test_function_to_tool():
    tool = function_to_tool(sample_fn)
    assert tool.name == "sample_fn"
    assert "label" in tool.parameters["properties"]
    assert "x" in tool.parameters["required"]


def test_registry_register_and_execute():
    registry = ToolRegistry()

    @registry.tool
    def double(n: int) -> int:
        """Double a number."""
        return n * 2

    assert len(registry.definitions) == 1
    result = registry.execute(ToolCall(id="1", name="double", arguments={"n": 21}))
    assert result == 42


def test_registry_execute_all():
    registry = ToolRegistry()

    @registry.tool
    def greet(name: str) -> str:
        """Greet someone."""
        return f"hi {name}"

    messages = registry.execute_all(
        [ToolCall(id="abc", name="greet", arguments={"name": "dev"})]
    )
    assert messages[0].content == "hi dev"
    assert messages[0].tool_call_id == "abc"
