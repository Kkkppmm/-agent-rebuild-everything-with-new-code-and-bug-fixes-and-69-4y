"""Structured output parsing utilities."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel

from devai.core.exceptions import ParseError

T = TypeVar("T", bound=BaseModel)


class StructuredParser:
    """Parse LLM output into structured data."""

    def __init__(self, model: type[T]) -> None:
        self.model = model

    def parse(self, text: str) -> T:
        return parse_model(text, self.model)


def parse_json(text: str) -> dict:
    """Extract and parse JSON from text, handling markdown code blocks."""
    cleaned = _extract_json(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Failed to parse JSON: {exc}") from exc


def parse_model(text: str, model: type[T]) -> T:
    """Parse text into a Pydantic model."""
    data = parse_json(text)
    try:
        return model.model_validate(data)
    except Exception as exc:
        raise ParseError(f"Failed to validate model: {exc}") from exc


def _extract_json(text: str) -> str:
    text = text.strip()
    code_block = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if code_block:
        return code_block.group(1).strip()
    brace_start = text.find("{")
    bracket_start = text.find("[")
    if brace_start == -1 and bracket_start == -1:
        return text
    start = min(s for s in [brace_start, bracket_start] if s != -1)
    return text[start:]
