"""Utility functions for DevAI."""

from __future__ import annotations

import re


def estimate_tokens(text: str) -> int:
  """Rough token estimate (~4 chars per token for English/code)."""
  if not text:
    return 0
  return max(1, len(text) // 4)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
  """Truncate text to approximate token limit."""
  max_chars = max_tokens * 4
  if len(text) <= max_chars:
    return text
  return text[:max_chars] + "\n... [truncated]"


def extract_code_blocks(text: str, language: str | None = None) -> list[str]:
  """Extract fenced code blocks from markdown text."""
  pattern = r"```(?:" + (re.escape(language) if language else r"\w*") + r")?\n(.*?)```"
  return re.findall(pattern, text, re.DOTALL)


def extract_json_block(text: str) -> str | None:
  """Extract JSON from markdown code block or raw text."""
  blocks = extract_code_blocks(text, "json")
  if blocks:
    return blocks[0].strip()
  match = re.search(r"\{.*\}", text, re.DOTALL)
  return match.group(0) if match else None


def format_file_tree(paths: list[str], root: str = "") -> str:
  """Format a list of file paths as a simple tree."""
  lines = []
  for path in sorted(paths):
    rel = path[len(root):].lstrip("/") if root and path.startswith(root) else path
    lines.append(f"  {rel}")
  return "\n".join(lines)
