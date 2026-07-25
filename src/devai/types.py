"""Core data types for DevAI."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ToolCall(BaseModel):
    """A tool invocation requested by the model."""

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class Message(BaseModel):
    """A single chat message."""

    role: Role | str
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[ToolCall] | None = None

    def to_dict(self) -> dict[str, Any]:
        role = self.role.value if isinstance(self.role, Role) else str(self.role)
        data: dict[str, Any] = {"role": role, "content": self.content}
        if self.name:
            data["name"] = self.name
        if self.tool_call_id:
            data["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            data["tool_calls"] = [tc.model_dump() for tc in self.tool_calls]
        return data


class ToolDefinition(BaseModel):
    """Schema describing a callable tool for the model."""

    name: str
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)

    def to_openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters or {"type": "object", "properties": {}},
            },
        }


class Usage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatResponse(BaseModel):
    """Response from a chat completion."""

    content: str
    model: str
    provider: str
    usage: Usage = Field(default_factory=Usage)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class StreamChunk(BaseModel):
    """A single chunk from a streaming response."""

    content: str = ""
    done: bool = False
    tool_calls: list[ToolCall] = Field(default_factory=list)
    usage: Usage | None = None


class EmbeddingResponse(BaseModel):
    """Response from an embedding request."""

    embeddings: list[list[float]]
    model: str
    provider: str
    usage: Usage = Field(default_factory=Usage)
