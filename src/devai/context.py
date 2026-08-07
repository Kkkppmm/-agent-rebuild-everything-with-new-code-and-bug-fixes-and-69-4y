"""DevContext and PromptBuilder — assemble LLM context from code, files, and git."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

from devai.core.models import Message
from devai.interpolate import interpolate
from devai.utils.diff import get_git_diff
from devai.utils.tokens import estimate_tokens, truncate_to_tokens


@dataclass
class ContextSection:
    """A labeled block of context text."""

    label: str
    content: str
    language: str | None = None

    def format(self) -> str:
        if self.language:
            return f"### {self.label}\n```{self.language}\n{self.content.rstrip()}\n```"
        return f"### {self.label}\n{self.content.rstrip()}"


@dataclass
class DevContext:
    """Fluent builder for assembling developer context for LLM prompts.

    Combine source files, code snippets, git diffs, and free text into a
    single formatted context block.

    Example::

        ctx = (
            DevContext()
            .file("src/main.py")
            .snippet("def add(a, b): return a + b", language="python", label="Target")
            .git_diff(staged=True)
            .vars(task="review for bugs")
        )
        prompt = ctx.build()
    """

    sections: list[ContextSection] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)
    base_path: Path | None = None
    max_tokens: int | None = None

    def with_base(self, path: str | Path) -> Self:
        """Set the base directory for relative file paths."""
        self.base_path = Path(path)
        return self

    def with_max_tokens(self, max_tokens: int) -> Self:
        """Truncate the built context to fit within a token budget."""
        self.max_tokens = max_tokens
        return self

    def text(self, content: str, *, label: str = "Notes") -> Self:
        """Add a free-text section."""
        self.sections.append(ContextSection(label=label, content=content))
        return self

    def snippet(
        self,
        code: str,
        *,
        language: str = "python",
        label: str | None = None,
    ) -> Self:
        """Add a fenced code snippet."""
        section_label = label or f"{language} code"
        self.sections.append(
            ContextSection(label=section_label, content=code, language=language)
        )
        return self

    def file(
        self,
        path: str | Path,
        *,
        label: str | None = None,
    ) -> Self:
        """Add the contents of a source file."""
        file_path = Path(path)
        if self.base_path is not None and not file_path.is_absolute():
            file_path = self.base_path / file_path
        if not file_path.exists():
            raise FileNotFoundError(f"Context file not found: {file_path}")
        content = file_path.read_text(encoding="utf-8", errors="replace")
        ext = file_path.suffix.lstrip(".")
        section_label = label or str(file_path)
        self.sections.append(
            ContextSection(label=section_label, content=content, language=ext or None)
        )
        return self

    def files(
        self,
        paths: list[str | Path],
        *,
        label_prefix: str = "",
    ) -> Self:
        """Add multiple source files."""
        for path in paths:
            p = Path(path)
            label = f"{label_prefix}{p}" if label_prefix else None
            self.file(p, label=label)
        return self

    def git_diff(
        self,
        *,
        staged: bool = False,
        base: str | None = None,
        label: str = "Git diff",
    ) -> Self:
        """Add the current git diff."""
        diff = get_git_diff(staged=staged, base=base)
        if diff.strip():
            self.sections.append(ContextSection(label=label, content=diff, language="diff"))
        return self

    def env(self, name: str, *, label: str | None = None) -> Self:
        """Add an environment variable value."""
        value = os.environ.get(name, "")
        section_label = label or f"env:{name}"
        self.sections.append(ContextSection(label=section_label, content=value))
        return self

    def vars(self, **kwargs: str) -> Self:
        """Add template variables for interpolation."""
        self.variables.update(kwargs)
        return self

    def section(self, label: str, content: str, *, language: str | None = None) -> Self:
        """Add a custom labeled section."""
        self.sections.append(ContextSection(label=label, content=content, language=language))
        return self

    def build(self) -> str:
        """Format all sections into a single context string."""
        if not self.sections:
            return ""
        parts = [s.format() for s in self.sections]
        text = "\n\n".join(parts)
        if self.variables:
            text = interpolate(text, self.variables, base_path=self.base_path)
        if self.max_tokens is not None:
            text = truncate_to_tokens(text, self.max_tokens)
        return text

    def token_count(self) -> int:
        """Estimate the token count of the built context."""
        return estimate_tokens(self.build())

    def to_messages(self, user_prompt: str, *, system: str | None = None) -> list[Message]:
        """Build chat messages with context prepended to the user prompt."""
        messages: list[Message] = []
        if system:
            messages.append(Message.system(system))
        context = self.build()
        if context:
            content = f"Context:\n{context}\n\n{user_prompt}"
        else:
            content = user_prompt
        messages.append(Message.user(content))
        return messages

    def to_dict(self) -> dict[str, Any]:
        """Serialize context for logging or program steps."""
        return {
            "sections": [
                {
                    "label": s.label,
                    "content": s.content,
                    "language": s.language,
                }
                for s in self.sections
            ],
            "variables": dict(self.variables),
            "token_count": self.token_count(),
        }

    @classmethod
    def from_files(
        cls,
        paths: list[str | Path],
        *,
        base_path: str | Path | None = None,
    ) -> DevContext:
        """Create context from a list of file paths."""
        ctx = cls()
        if base_path is not None:
            ctx.with_base(base_path)
        return ctx.files(paths)


@dataclass
class PromptBuilder:
    """Fluent builder for structured LLM prompts with context and examples.

    Example::

        messages = (
            PromptBuilder()
            .system("You are a senior Python reviewer.")
            .context(DevContext().snippet("def f(): pass"))
            .user("Find bugs in the code above.")
            .build()
        )
    """

    _messages: list[Message] = field(default_factory=list)
    _context: DevContext | None = None
    _pending_user: str | None = None

    def system(self, text: str) -> Self:
        """Add a system message."""
        self._messages.append(Message.system(text))
        return self

    def user(self, text: str) -> Self:
        """Add a user message (context is prepended when build() is called)."""
        self._pending_user = text
        return self

    def assistant(self, text: str) -> Self:
        """Add an assistant message (useful for few-shot examples)."""
        self._flush_pending()
        self._messages.append(Message.assistant(text))
        return self

    def context(self, ctx: DevContext) -> Self:
        """Attach a DevContext to prepend to the next user message."""
        self._context = ctx
        return self

    def example(self, user: str, assistant: str) -> Self:
        """Add a few-shot example pair."""
        self._flush_pending()
        self._messages.append(Message.user(user))
        self._messages.append(Message.assistant(assistant))
        return self

    def _flush_pending(self) -> None:
        if self._pending_user is None:
            return
        user_text = self._pending_user
        if self._context is not None:
            user_text = interpolate(
                user_text,
                self._context.variables,
                base_path=self._context.base_path,
            )
            built = self._context.build()
            if built:
                content = f"Context:\n{built}\n\n{user_text}"
            else:
                content = user_text
            self._context = None
        else:
            content = user_text
        self._messages.append(Message.user(content))
        self._pending_user = None

    def build(self) -> list[Message]:
        """Return the assembled message list."""
        self._flush_pending()
        return list(self._messages)

    def build_string(self) -> str:
        """Return a single string representation of all messages."""
        parts: list[str] = []
        for msg in self.build():
            role = msg.role if isinstance(msg.role, str) else msg.role.value
            parts.append(f"[{role.upper()}]\n{msg.content}")
        return "\n\n".join(parts)
