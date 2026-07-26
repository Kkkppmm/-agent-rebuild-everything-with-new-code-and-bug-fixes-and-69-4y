"""Conversation memory for multi-turn interactions."""

from devai.core.models import Message, Role
from devai.utils.text import estimate_tokens, truncate_to_tokens


class ConversationMemory:
    """Stores conversation history with optional token-based truncation."""

    def __init__(self, max_tokens: int = 4000) -> None:
        self.messages: list[Message] = []
        self.max_tokens = max_tokens

    def add(self, message: Message) -> None:
        self.messages.append(message)
        self._truncate()

    def add_user(self, content: str) -> None:
        self.add(Message(role=Role.USER, content=content))

    def add_assistant(self, content: str) -> None:
        self.add(Message(role=Role.ASSISTANT, content=content))

    def add_system(self, content: str) -> None:
        self.add(Message(role=Role.SYSTEM, content=content))

    def get_messages(self) -> list[Message]:
        return list(self.messages)

    def clear(self) -> None:
        self.messages.clear()

    def _truncate(self) -> None:
        total = sum(estimate_tokens(m.content) for m in self.messages)
        while total > self.max_tokens and len(self.messages) > 1:
            removed = self.messages.pop(0)
            total -= estimate_tokens(removed.content)

    def summary(self) -> str:
        return truncate_to_tokens(
            "\n".join(f"{m.role.value}: {m.content}" for m in self.messages),
            self.max_tokens,
        )

    def __len__(self) -> int:
        return len(self.messages)
