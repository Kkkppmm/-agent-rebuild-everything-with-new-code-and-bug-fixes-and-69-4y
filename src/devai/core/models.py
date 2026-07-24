"""Data models for DevAI."""

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class Message:
    """A chat message."""

    role: Literal["system", "user", "assistant", "tool"]
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list["ToolCall"] | None = None


@dataclass
class ToolCall:
    """A tool invocation requested by the model."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolDefinition:
    """Schema for a tool available to the model."""

    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters or {
                    "type": "object",
                    "properties": {},
                },
            },
        }


@dataclass
class LLMResponse:
    """Response from an LLM completion."""

    content: str
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    tool_calls: list[ToolCall] | None = None
    raw: Any = None

    @property
    def has_tool_calls(self) -> bool:
        return self.tool_calls is not None and len(self.tool_calls) > 0
