"""Structured output parsing utilities."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel

from devai.core.exceptions import ParseError

T = TypeVar("T", bound=BaseModel)


def parse_json(text: str) -> dict | list:
    """Parse JSON from text, extracting from code blocks if needed."""
    text = text.strip()
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        text = match.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Failed to parse JSON: {exc}") from exc


def parse_model(text: str, model: type[T]) -> T:
    """Parse text into a Pydantic model."""
    data = parse_json(text)
    try:
        return model.model_validate(data)
    except Exception as exc:
        raise ParseError(f"Failed to validate model {model.__name__}: {exc}") from exc


class StructuredParser:
    """Parser for extracting structured data from LLM responses."""

    def __init__(self, model: type[T]):
        self.model = model

    def parse(self, text: str) -> T:
        return parse_model(text, self.model)

    def get_schema_prompt(self) -> str:
        return f"Respond with valid JSON matching this schema:\n{self.model.model_json_schema()}"
