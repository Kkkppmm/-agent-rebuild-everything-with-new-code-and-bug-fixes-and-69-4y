"""Structured output parsing utilities."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel

from devai.core.exceptions import ParseError

T = TypeVar("T", bound=BaseModel)


def extract_json(text: str) -> str:
    """Extract JSON object or array from mixed text."""
    text = text.strip()
    if text.startswith("{") or text.startswith("["):
        return text
    match = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
    if match:
        return match.group(1)
    raise ParseError("No JSON found in response")


def parse_json(text: str) -> dict | list:
    """Parse JSON from LLM output, tolerating markdown fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        return json.loads(extract_json(cleaned))
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid JSON: {exc}") from exc


def parse_model(text: str, model: type[T]) -> T:
    """Parse LLM output into a Pydantic model."""
    data = parse_json(text)
    try:
        return model.model_validate(data)
    except Exception as exc:
        raise ParseError(f"Failed to validate {model.__name__}: {exc}") from exc


class StructuredParser:
    """Reusable parser for a specific Pydantic model."""

    def __init__(self, model: type[T]) -> None:
        self.model = model

    def parse(self, text: str) -> T:
        return parse_model(text, self.model)
