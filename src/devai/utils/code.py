"""Code parsing and extraction utilities."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class CodeBlock:
  """A fenced code block extracted from markdown."""

  language: str
  code: str
  index: int


_CODE_BLOCK_RE = re.compile(
  r"```(\w*)\n(.*?)```",
  re.DOTALL,
)


def extract_code_blocks(text: str) -> list[CodeBlock]:
  """Extract fenced code blocks from markdown text."""
  blocks: list[CodeBlock] = []
  for i, match in enumerate(_CODE_BLOCK_RE.finditer(text)):
    blocks.append(
      CodeBlock(
        language=match.group(1) or "text",
        code=match.group(2).strip(),
        index=i,
      )
    )
  return blocks


def extract_first_code_block(text: str, language: str | None = None) -> str | None:
  """Return the first code block, optionally filtered by language."""
  for block in extract_code_blocks(text):
    if language is None or block.language == language:
      return block.code
  return None


def strip_code_fences(text: str) -> str:
  """Remove markdown code fences from text."""
  return _CODE_BLOCK_RE.sub(lambda m: m.group(2).strip(), text)
