"""Data models for messages, tools, and completions."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Role(str, Enum):
  USER = "user"
  ASSISTANT = "assistant"
  SYSTEM = "system"
  TOOL = "tool"


class Message(BaseModel):
  role: Role
  content: str
  name: str | None = None
  tool_call_id: str | None = None
  tool_calls: list[ToolCall] | None = None

  def to_dict(self) -> dict[str, Any]:
    data: dict[str, Any] = {"role": self.role.value, "content": self.content}
    if self.name:
      data["name"] = self.name
    if self.tool_call_id:
      data["tool_call_id"] = self.tool_call_id
    if self.tool_calls:
      data["tool_calls"] = [tc.model_dump() for tc in self.tool_calls]
    return data


class ToolCall(BaseModel):
  id: str
  name: str
  arguments: dict[str, Any] = Field(default_factory=dict)


class ToolDefinition(BaseModel):
  name: str
  description: str
  parameters: dict[str, Any] = Field(default_factory=dict)

  def to_openai_schema(self) -> dict[str, Any]:
    return {
      "type": "function",
      "function": {
        "name": self.name,
        "description": self.description,
        "parameters": self.parameters,
      },
    }


class CompletionResult(BaseModel):
  content: str
  model: str = ""
  finish_reason: str | None = None
  tool_calls: list[ToolCall] | None = None
  usage: dict[str, int] = Field(default_factory=dict)

  @property
  def text(self) -> str:
    return self.content
