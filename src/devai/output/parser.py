"""Structured output parsing."""

from __future__ import annotations

import json
import re
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ValidationError

from devai.core.exceptions import ParseError

T = TypeVar("T", bound=BaseModel)


def parse_json(text: str) -> dict[str, Any]:
    """Extract and parse JSON from text, handling markdown code blocks."""
    text = text.strip()
    code_block = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if code_block:
        text = code_block.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError as exc:
                raise ParseError(f"Failed to parse JSON: {text[:200]}") from exc
        raise ParseError(f"No valid JSON found in: {text[:200]}")


def parse_model(text: str, model: type[T]) -> T:
    """Parse text into a Pydantic model."""
    data = parse_json(text) if not text.strip().startswith("{") else json.loads(text)
    try:
        return model.model_validate(data)
    except (json.JSONDecodeError, ValidationError) as exc:
        if isinstance(exc, json.JSONDecodeError):
            data = parse_json(text)
            return model.model_validate(data)
        raise ParseError(f"Validation failed: {exc}") from exc


class StructuredParser(Generic[T]):  # noqa: F821
    """Parser for structured Pydantic output."""

    def __init__(self, model: type[T]) -> None:
        self.model = model

    def parse(self, data: dict[str, Any] | str) -> T:
        if isinstance(data, str):
            return parse_model(data, self.model)
        try:
            return self.model.model_validate(data)
        except ValidationError as exc:
            raise ParseError(f"Validation failed: {exc}") from exc

    def parse_response(self, text: str) -> T:
        return parse_model(text, self.model)
