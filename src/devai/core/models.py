"""Data models for messages, tools, and responses."""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Role(str, Enum):
  """Message roles supported by chat APIs."""

  SYSTEM = "system"
  USER = "user"
  ASSISTANT = "assistant"
  TOOL = "tool"


class Message(BaseModel):
  """A single chat message."""

  role: Role
  content: str
  name: str | None = None
  tool_calls: list[ToolCall] | None = None
  tool_call_id: str | None = None

  def to_api_dict(self) -> dict[str, Any]:
    """Serialize to OpenAI-compatible chat message format."""
    data: dict[str, Any] = {"role": self.role.value, "content": self.content}
    if self.name:
      data["name"] = self.name
    if self.tool_calls:
      data["tool_calls"] = [
        {
          "id": tc.id,
          "type": "function",
          "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
        }
        for tc in self.tool_calls
      ]
    if self.tool_call_id:
      data["tool_call_id"] = self.tool_call_id
    return data

  @classmethod
  def system(cls, content: str) -> Message:
    return cls(role=Role.SYSTEM, content=content)

  @classmethod
  def user(cls, content: str) -> Message:
    return cls(role=Role.USER, content=content)

  @classmethod
  def assistant(cls, content: str, tool_calls: list[ToolCall] | None = None) -> Message:
    return cls(role=Role.ASSISTANT, content=content, tool_calls=tool_calls)

  @classmethod
  def tool(cls, content: str, tool_call_id: str) -> Message:
    return cls(role=Role.TOOL, content=content, tool_call_id=tool_call_id)


class ToolCall(BaseModel):
  """A tool invocation requested by the model."""

  id: str
  name: str
  arguments: dict[str, Any] = Field(default_factory=dict)


class ToolDefinition(BaseModel):
  """Schema describing a callable tool for the LLM."""

  name: str
  description: str
  parameters: dict[str, Any] = Field(default_factory=dict)

  def to_api_dict(self) -> dict[str, Any]:
    return {
      "type": "function",
      "function": {
        "name": self.name,
        "description": self.description,
        "parameters": self.parameters,
      },
    }


class ChatResponse(BaseModel):
  """Response from an LLM chat completion."""

  content: str
  tool_calls: list[ToolCall] = Field(default_factory=list)
  model: str = ""
  finish_reason: str = ""
  usage: dict[str, int] = Field(default_factory=dict)

  @property
  def has_tool_calls(self) -> bool:
    return len(self.tool_calls) > 0
