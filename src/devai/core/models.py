"""Data models for DevAI."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Role(str, Enum):
  SYSTEM = "system"
  USER = "user"
  ASSISTANT = "assistant"
  TOOL = "tool"


class Message(BaseModel):
  role: Role
  content: str
  name: str | None = None
  tool_calls: list[ToolCall] | None = None
  tool_call_id: str | None = None

  def to_dict(self) -> dict[str, Any]:
    data: dict[str, Any] = {"role": self.role.value, "content": self.content}
    if self.name:
      data["name"] = self.name
    if self.tool_calls:
      data["tool_calls"] = [tc.model_dump() for tc in self.tool_calls]
    if self.tool_call_id:
      data["tool_call_id"] = self.tool_call_id
    return data


class ToolCall(BaseModel):
  id: str
  name: str
  arguments: dict[str, Any] = Field(default_factory=dict)


class ToolDefinition(BaseModel):
  name: str
  description: str
  parameters: dict[str, Any] = Field(default_factory=dict)

  def to_openai_tool(self) -> dict[str, Any]:
    return {
      "type": "function",
      "function": {
        "name": self.name,
        "description": self.description,
        "parameters": self.parameters or {"type": "object", "properties": {}},
      },
    }


class CompletionResult(BaseModel):
  content: str
  tool_calls: list[ToolCall] = Field(default_factory=list)
  finish_reason: str = "stop"
  usage: dict[str, int] = Field(default_factory=dict)
  raw: dict[str, Any] = Field(default_factory=dict)
