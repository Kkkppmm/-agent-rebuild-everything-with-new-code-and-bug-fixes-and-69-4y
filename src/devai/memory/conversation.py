"""Conversation memory for DevAI."""

from devai.core.models import Message


class ConversationMemory:
    """Stores conversation history with optional windowing."""

    def __init__(self, max_messages: int = 50) -> None:
        self.max_messages = max_messages
        self._messages: list[Message] = []

    def add(self, message: Message) -> None:
        self._messages.append(message)
        if len(self._messages) > self.max_messages:
            self._messages = self._messages[-self.max_messages:]

    def add_user(self, content: str) -> None:
        self.add(Message(role="user", content=content))

    def add_assistant(self, content: str) -> None:
        self.add(Message(role="assistant", content=content))

    def get_messages(self) -> list[Message]:
        return list(self._messages)

    def clear(self) -> None:
        self._messages.clear()

    def __len__(self) -> int:
        return len(self._messages)

    @property
    def last(self) -> Message | None:
        return self._messages[-1] if self._messages else None

    def to_prompt(self) -> str:
        parts = []
        for m in self._messages:
            parts.append(f"{m.role}: {m.content}")
        return "\n".join(parts)
