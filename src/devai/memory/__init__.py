"""Conversation memory for multi-turn interactions."""

from __future__ import annotations

from devai.core.models import Message, Role, ToolCall


class ConversationMemory:
    """Stores conversation history for agents and assistants."""

    def __init__(self, max_messages: int = 50) -> None:
        self._messages: list[Message] = []
        self.max_messages = max_messages

    def add(
        self,
        role: Role | str,
        content: str,
        *,
        tool_calls: list[ToolCall] | None = None,
        tool_call_id: str | None = None,
        name: str | None = None,
    ) -> None:
        self._messages.append(
            Message(
                role=role,
                content=content,
                tool_calls=tool_calls,
                tool_call_id=tool_call_id,
                name=name,
            )
        )
        if len(self._messages) > self.max_messages:
            self._messages = self._messages[-self.max_messages :]

    def get_messages(self) -> list[Message]:
        return list(self._messages)

    def clear(self) -> None:
        self._messages.clear()

    def last(self) -> Message | None:
        return self._messages[-1] if self._messages else None

    @property
    def message_count(self) -> int:
        return len(self._messages)
