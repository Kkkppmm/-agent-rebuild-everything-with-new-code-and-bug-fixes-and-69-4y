"""Extract fenced code blocks from LLM responses."""

from __future__ import annotations

import re
from dataclasses import dataclass

_FENCE_PATTERN = re.compile(
    r"```(?P<lang>[\w+#.-]*)\n(?P<code>.*?)```",
    re.DOTALL,
)


@dataclass(frozen=True)
class CodeBlock:
    """A fenced code block extracted from LLM output."""

    language: str | None
    code: str
    start: int
    end: int


def extract_code_blocks(text: str) -> list[CodeBlock]:
    """Extract all fenced code blocks from text.

    Supports standard markdown fences like:

    ```python
    def hello():
        pass
    ```
    """
    blocks: list[CodeBlock] = []
    for match in _FENCE_PATTERN.finditer(text):
        lang = match.group("lang").strip() or None
        code = match.group("code").rstrip("\n")
        blocks.append(
            CodeBlock(
                language=lang,
                code=code,
                start=match.start(),
                end=match.end(),
            )
        )
    return blocks


def extract_first_code_block(text: str, language: str | None = None) -> str | None:
    """Return the first fenced code block, optionally filtered by language."""
    for block in extract_code_blocks(text):
        if language is None or block.language == language:
            return block.code
    return None


def extract_code_by_language(text: str) -> dict[str, list[str]]:
    """Group extracted code blocks by language tag."""
    grouped: dict[str, list[str]] = {}
    for block in extract_code_blocks(text):
        key = block.language or "text"
        grouped.setdefault(key, []).append(block.code)
    return grouped
