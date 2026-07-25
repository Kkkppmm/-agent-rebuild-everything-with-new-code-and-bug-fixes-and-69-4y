"""Conversation memory for agents."""

from __future__ import annotations

from devai.core.models import Message, Role, ToolCall
from devai.utils.helpers import estimate_tokens, truncate_to_tokens


class ConversationMemory:
    """Stores conversation history with optional token-based truncation."""

    def __init__(self, max_tokens: int | None = None):
        self._messages: list[Message] = []
        self.max_tokens = max_tokens

    def add(
        self,
        role: Role | str,
        content: str,
        *,
        tool_calls: list[ToolCall] | None = None,
        tool_call_id: str | None = None,
        name: str | None = None,
    ) -> None:
        if isinstance(role, str):
            role = Role(role)
        self._messages.append(
            Message(
                role=role,
                content=content,
                tool_calls=tool_calls,
                tool_call_id=tool_call_id,
                name=name,
            )
        )
        if self.max_tokens:
            self._truncate()

    def add_tool_result(self, tool_call_id: str, result: str) -> None:
        self.add(Role.TOOL, result, tool_call_id=tool_call_id)

    def get_messages(self) -> list[Message]:
        return list(self._messages)

    def clear(self) -> None:
        self._messages.clear()

    def __len__(self) -> int:
        return len(self._messages)

    @property
    def token_count(self) -> int:
        text = " ".join(m.content for m in self._messages)
        return estimate_tokens(text)

    def _truncate(self) -> None:
        if not self.max_tokens:
            return
        while self._messages and self.token_count > self.max_tokens:
            self._messages.pop(0)

    def to_dict_list(self) -> list[dict]:
        return [m.to_dict() for m in self._messages]

    def summary(self) -> str:
        lines = []
        for m in self._messages:
            prefix = m.role.value.upper()
            content = truncate_to_tokens(m.content, 100)
            lines.append(f"[{prefix}] {content}")
        return "\n".join(lines)
