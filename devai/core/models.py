"""Shared data models for DevAI."""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Role(str, Enum):
  """Chat message roles."""

  SYSTEM = "system"
  USER = "user"
  ASSISTANT = "assistant"
  TOOL = "tool"


class Message(BaseModel):
  """A single chat message."""

  role: Role
  content: str
  name: str | None = None
  tool_call_id: str | None = None
  tool_calls: list[ToolCall] | None = None

  def to_api_dict(self) -> dict[str, Any]:
    """Serialize to an OpenAI-compatible message dict."""
    data: dict[str, Any] = {"role": self.role.value, "content": self.content}
    if self.name:
      data["name"] = self.name
    if self.tool_call_id:
      data["tool_call_id"] = self.tool_call_id
    if self.tool_calls:
      data["tool_calls"] = [call.to_api_dict() for call in self.tool_calls]
    return data


class ToolCall(BaseModel):
  """A tool invocation requested by the model."""

  id: str
  name: str
  arguments: dict[str, Any] = Field(default_factory=dict)

  @classmethod
  def from_api_dict(cls, data: dict[str, Any]) -> ToolCall:
    function = data.get("function", {})
    raw_args = function.get("arguments", "{}")
    if isinstance(raw_args, str):
      arguments = json.loads(raw_args) if raw_args else {}
    else:
      arguments = raw_args
    return cls(id=data["id"], name=function["name"], arguments=arguments)

  def to_api_dict(self) -> dict[str, Any]:
    return {
      "id": self.id,
      "type": "function",
      "function": {
        "name": self.name,
        "arguments": json.dumps(self.arguments),
      },
    }


class ToolDefinition(BaseModel):
  """Schema describing a callable tool."""

  name: str
  description: str
  parameters: dict[str, Any] = Field(default_factory=dict)

  def to_api_dict(self) -> dict[str, Any]:
    return {
      "type": "function",
      "function": {
        "name": self.name,
        "description": self.description,
        "parameters": self.parameters or {"type": "object", "properties": {}},
      },
    }


class CompletionResult(BaseModel):
  """Normalized response from an LLM completion."""

  content: str | None = None
  tool_calls: list[ToolCall] = Field(default_factory=list)
  finish_reason: str | None = None
  usage: dict[str, int] = Field(default_factory=dict)
  raw: dict[str, Any] = Field(default_factory=dict)

  @property
  def has_tool_calls(self) -> bool:
    return bool(self.tool_calls)
