"""Structured output parsing utilities."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel

from devai.core.exceptions import ParseError

T = TypeVar("T", bound=BaseModel)


def extract_json(text: str) -> str:
    """Extract JSON from text that may contain markdown code fences."""
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fence_match:
        return fence_match.group(1).strip()
    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        return brace_match.group(0)
    return text.strip()


def parse_json(text: str) -> dict:
    """Parse JSON from LLM output, handling common formatting issues."""
    try:
        return json.loads(extract_json(text))
    except json.JSONDecodeError as exc:
        raise ParseError(f"Failed to parse JSON: {exc}") from exc


def parse_model(text: str, model: type[T]) -> T:
    """Parse LLM output into a Pydantic model."""
    data = parse_json(text)
    try:
        return model.model_validate(data)
    except Exception as exc:
        raise ParseError(f"Failed to validate model: {exc}") from exc


class StructuredParser:
    """Parser for structured LLM outputs."""

    def __init__(self, model: type[T]) -> None:
        self.model = model

    def parse(self, text: str) -> T:
        return parse_model(text, self.model)
