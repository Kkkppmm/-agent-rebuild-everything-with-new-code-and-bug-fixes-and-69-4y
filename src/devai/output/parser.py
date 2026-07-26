"""Output parsing utilities."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from devai.core.exceptions import ParseError

T = TypeVar("T", bound=BaseModel)


def parse_json(text: str) -> dict:
    """Extract and parse JSON from LLM output."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON in code block: {exc}") from exc

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON object: {exc}") from exc

    raise ParseError("No valid JSON found in response")


def parse_model(text: str, model: type[T]) -> T:
    """Parse LLM output into a Pydantic model."""
    data = parse_json(text)
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise ParseError(f"Failed to validate model: {exc}") from exc


class StructuredParser:
    """Parser for structured LLM outputs."""

    def __init__(self, model: type[BaseModel] | None = None):
        self.model = model

    def parse(self, text: str) -> dict | BaseModel:
        if self.model:
            return parse_model(text, self.model)
        return parse_json(text)
