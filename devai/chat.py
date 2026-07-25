"""Chat messages and conversation sessions."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from devai.types import ChatResponse


class Role(str, Enum):
    """Message roles for chat completions."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class Message:
    """A single chat message."""

    role: Role | str
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        role = self.role.value if isinstance(self.role, Role) else str(self.role)
        data: dict[str, Any] = {"role": role, "content": self.content}
        if self.name:
            data["name"] = self.name
        if self.tool_call_id:
            data["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            data["tool_calls"] = self.tool_calls
        return data


@dataclass
class ChatSession:
    """Stateful conversation that tracks message history."""

    system: str | None = None
    messages: list[Message] = field(default_factory=list)
    max_history: int | None = None

    def add(self, role: Role | str, content: str, **kwargs: Any) -> Message:
        """Append a message to the session."""
        msg = Message(role=role, content=content, **kwargs)
        self.messages.append(msg)
        self._trim_history()
        return msg

    def add_user(self, content: str) -> Message:
        return self.add(Role.USER, content)

    def add_assistant(self, content: str, tool_calls: list[dict[str, Any]] | None = None) -> Message:
        return self.add(Role.ASSISTANT, content, tool_calls=tool_calls)

    def add_system(self, content: str) -> Message:
        return self.add(Role.SYSTEM, content)

    def add_tool_result(self, tool_call_id: str, content: str) -> Message:
        return self.add(Role.TOOL, content, tool_call_id=tool_call_id)

    def to_messages(self) -> list[dict[str, Any]]:
        """Serialize session to provider message format."""
        out: list[dict[str, Any]] = []
        if self.system:
            out.append({"role": "system", "content": self.system})
        out.extend(m.to_dict() for m in self.messages)
        return out

    def clear(self) -> None:
        """Remove all messages (system prompt preserved)."""
        self.messages.clear()

    def _trim_history(self) -> None:
        if self.max_history is not None and len(self.messages) > self.max_history:
            self.messages = self.messages[-self.max_history:]

    def complete(
        self,
        client: Any,
        user_message: str | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> ChatResponse:
        """Send session to client and record assistant reply."""
        if user_message:
            self.add_user(user_message)
        response = client.chat_messages(
            messages=self.to_messages(),
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
            **kwargs,
        )
        self.add_assistant(response.content, tool_calls=response.tool_calls or None)
        return response

    async def complete_async(
        self,
        client: Any,
        user_message: str | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> ChatResponse:
        if user_message:
            self.add_user(user_message)
        response = await client.chat_messages_async(
            messages=self.to_messages(),
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
            **kwargs,
        )
        self.add_assistant(response.content, tool_calls=response.tool_calls or None)
        return response

    def stream(
        self,
        client: Any,
        user_message: str | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        if user_message:
            self.add_user(user_message)
        parts: list[str] = []
        for token in client.chat_messages_stream(
            messages=self.to_messages(),
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        ):
            parts.append(token)
            yield token
        self.add_assistant("".join(parts))

    async def stream_async(
        self,
        client: Any,
        user_message: str | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        if user_message:
            self.add_user(user_message)
        parts: list[str] = []
        async for token in client.chat_messages_stream_async(
            messages=self.to_messages(),
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        ):
            parts.append(token)
            yield token
        self.add_assistant("".join(parts))
