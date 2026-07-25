"""Structured output parsing for LLM responses."""

from __future__ import annotations

import json
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from devai.core.exceptions import ParseError
from devai.utils.helpers import extract_json

T = TypeVar("T", bound=BaseModel)


def parse_json(text: str) -> dict[str, Any]:
    """Parse a JSON object from LLM output text."""
    raw = extract_json(text)
    if raw is None:
        raise ParseError("No JSON object found in response")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ParseError("Expected a JSON object")
    return data


def parse_model(text: str, model: type[T]) -> T:
    """Parse LLM output into a Pydantic model."""
    data = parse_json(text)
    try:
        return model.model_validate(data)
    except ValidationError as e:
        raise ParseError(f"Validation failed: {e}") from e


class StructuredParser:
    """Reusable parser for a specific Pydantic output schema."""

    def __init__(self, model: type[T]):
        self.model = model

    def parse(self, text: str) -> T:
        return parse_model(text, self.model)
