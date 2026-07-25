"""Tests for DevAI core models."""



from devai.core.models import Message, Role, ToolCall, ToolDefinition


def test_message_to_api_dict():
    msg = Message(role=Role.USER, content="hello")
    assert msg.to_api_dict() == {"role": "user", "content": "hello"}


def test_tool_call_roundtrip():
    api_data = {
        "id": "call_1",
        "type": "function",
        "function": {"name": "search", "arguments": '{"query": "devai"}'},
    }
    call = ToolCall.from_api_dict(api_data)
    assert call.name == "search"
    assert call.arguments == {"query": "devai"}
    assert call.to_api_dict()["function"]["name"] == "search"


def test_tool_definition_schema():
    tool = ToolDefinition(
        name="greet",
        description="Say hello",
        parameters={
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    )
    api = tool.to_api_dict()
    assert api["function"]["name"] == "greet"


def test_completion_result_has_tool_calls():
    from devai.core.models import CompletionResult

    result = CompletionResult(tool_calls=[ToolCall(id="1", name="t", arguments={})])
    assert result.has_tool_calls is True

    empty = CompletionResult(content="hi")
    assert empty.has_tool_calls is False
