"""Tests for core types."""

from devai.prompts import ChatPrompt, PromptTemplate
from devai.types import Message, Role, ToolCall, ToolDefinition


def test_message_to_dict():
    msg = Message(role=Role.USER, content="hello")
    assert msg.to_dict() == {"role": "user", "content": "hello"}


def test_tool_definition_openai_schema():
    tool = ToolDefinition(
        name="search",
        description="Search docs",
        parameters={"type": "object", "properties": {"q": {"type": "string"}}},
    )
    schema = tool.to_openai_schema()
    assert schema["function"]["name"] == "search"


def test_prompt_template_format():
    tpl = PromptTemplate("Hello {name}!")
    assert tpl.format(name="World") == "Hello World!"
    assert tpl.variables == {"name"}


def test_chat_prompt_builder():
    messages = ChatPrompt().system("sys").user("hi").build()
    assert len(messages) == 2
    assert messages[0].role == Role.SYSTEM
    assert messages[1].content == "hi"


def test_tool_call_model():
    tc = ToolCall(id="1", name="fn", arguments={"x": 1})
    assert tc.name == "fn"
