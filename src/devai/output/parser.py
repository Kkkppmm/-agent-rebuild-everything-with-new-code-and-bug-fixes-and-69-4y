"""Structured output parsing for DevAI."""

import json
import re
from typing import Any, Type, TypeVar

from pydantic import BaseModel

from devai.core.exceptions import ParseError

T = TypeVar("T", bound=BaseModel)


def parse_json(text: str) -> dict[str, Any]:
    """Extract and parse JSON from text, handling markdown code blocks."""
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from code block
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding JSON object in text
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    raise ParseError(f"Could not parse JSON from: {text[:200]}")


def parse_model(text: str, model: Type[T]) -> T:
    """Parse text into a Pydantic model."""
    data = parse_json(text)
    return model.model_validate(data)


class StructuredParser:
    """Parser for structured LLM outputs."""

    def __init__(self, model: Type[BaseModel]) -> None:
        self.model = model

    def parse(self, text: str) -> BaseModel:
        return parse_model(text, self.model)

    def parse_safe(self, text: str) -> BaseModel | None:
        try:
            return self.parse(text)
        except ParseError:
            return None
