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
        """Serialize conversation state to a JSON-compatible dict."""
        return {
            "max_tokens": self.max_tokens,
            "messages": [m.to_dict() for m in self.messages],
        }

    @classmethod
    def from_dict(cls, data: dict) -> ConversationMemory:
        """Restore conversation state from a dict."""
        mem = cls(max_tokens=data.get("max_tokens", 8000))
        mem.messages = [Message.from_dict(m) for m in data.get("messages", [])]
        return mem

    def save(self, path: str | Path) -> None:
        """Persist conversation to a JSON file."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> ConversationMemory:
        """Load conversation from a JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)


class ConversationStore:
    """Named conversation sessions with file-backed persistence."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path_for(self, name: str) -> Path:
        safe = name.replace("/", "_").replace("\\", "_")
        return self.directory / f"{safe}.json"

    def get(self, name: str, *, max_tokens: int = 8000) -> ConversationMemory:
        """Load or create a named conversation."""
        path = self._path_for(name)
        if path.exists():
            return ConversationMemory.load(path)
        return ConversationMemory(max_tokens=max_tokens)

    def save(self, name: str, memory: ConversationMemory) -> None:
        """Persist a named conversation."""
        memory.save(self._path_for(name))

    def delete(self, name: str) -> bool:
        """Remove a named conversation file."""
        path = self._path_for(name)
        if path.exists():
            path.unlink()
            return True
        return False

    def list_names(self) -> list[str]:
        """List all stored conversation names."""
        return sorted(p.stem for p in self.directory.glob("*.json"))
