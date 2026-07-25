"""Shared type definitions for devai."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class Role(str, Enum):
  USER = "user"
  ASSISTANT = "assistant"
  SYSTEM = "system"
  TOOL = "tool"


@dataclass
class Message:
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
      data["tool_calls"] = [tc.to_dict() for tc in self.tool_calls]
    return data


@dataclass
class ToolCall:
  id: str
  name: str
  arguments: dict[str, Any]

  def to_dict(self) -> dict[str, Any]:
    import json

    return {
      "id": self.id,
      "type": "function",
      "function": {
        "name": self.name,
        "arguments": json.dumps(self.arguments),
      },
    }


@dataclass
class ToolDefinition:
  name: str
  description: str
  parameters: dict[str, Any]
  func: Callable[..., Any] | None = None

  def to_schema(self) -> dict[str, Any]:
    return {
      "type": "function",
      "function": {
        "name": self.name,
        "description": self.description,
        "parameters": self.parameters,
      },
    }


@dataclass
class ChatResponse:
  content: str
  role: str = "assistant"
  tool_calls: list[ToolCall] | None = None
  model: str | None = None
  usage: dict[str, int] | None = None
  raw: dict[str, Any] | None = None


@dataclass
class StreamChunk:
  content: str = ""
  done: bool = False
  tool_calls: list[ToolCall] | None = None


@dataclass
class EmbeddingResponse:
  embeddings: list[list[float]]
  model: str | None = None
  usage: dict[str, int] | None = None


@dataclass
class ProviderConfig:
  api_key: str | None = None
  base_url: str | None = None
  model: str | None = None
  timeout: float = 60.0
  extra: dict[str, Any] = field(default_factory=dict)
