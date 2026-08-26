"""Conversation memory for DevAI."""

from __future__ import annotations

import json
from pathlib import Path

from devai.core.models import Message, Role
from devai.utils import estimate_tokens


class ConversationMemory:
    """Store and manage conversation history with token limits."""

    def __init__(self, max_tokens: int = 8000, system_message: str | None = None) -> None:
        self.max_tokens = max_tokens
        self.messages: list[Message] = []
        if system_message:
            self.messages.append(Message.system(system_message))

    def add(self, message: Message) -> None:
        self.messages.append(message)
        self._trim()

    def add_user(self, content: str) -> None:
        self.add(Message.user(content))

    def add_assistant(self, content: str) -> None:
        self.add(Message.assistant(content))

    def get_messages(self) -> list[Message]:
        return list(self.messages)

    def clear(self) -> None:
        system = [m for m in self.messages if m.role == Role.SYSTEM]
        self.messages = system

    def _trim(self) -> None:
        total = sum(estimate_tokens(m.content) for m in self.messages)
        while total > self.max_tokens and len(self.messages) > 1:
            # Keep system messages, remove oldest non-system
            for i, msg in enumerate(self.messages):
                if msg.role != Role.SYSTEM:
                    removed = self.messages.pop(i)
                    total -= estimate_tokens(removed.content)
                    break
            else:
                break

    @property
    def token_count(self) -> int:
        return sum(estimate_tokens(m.content) for m in self.messages)

    def __len__(self) -> int:
        return len(self.messages)

    def to_dict(self) -> dict:
        """Serialize memory to a JSON-compatible dict."""
        return {
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": m.role.value, "content": m.content}
                for m in self.messages
            ],
        }

    def save(self, path: str | Path) -> None:
        """Persist conversation memory to a JSON file."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def from_dict(cls, data: dict) -> ConversationMemory:
        """Restore memory from a serialized dict."""
        mem = cls(max_tokens=data.get("max_tokens", 8000))
        for item in data.get("messages", []):
            role = Role(item["role"])
            mem.messages.append(Message(role=role, content=item["content"]))
        return mem

    @classmethod
    def load(cls, path: str | Path) -> ConversationMemory:
        """Load conversation memory from a JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)
