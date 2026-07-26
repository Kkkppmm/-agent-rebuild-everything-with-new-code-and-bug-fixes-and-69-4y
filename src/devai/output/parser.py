"""Parse structured output from LLM responses."""

from __future__ import annotations

import json
import re
from typing import Any, TypeVar

from pydantic import BaseModel

from devai.core.exceptions import ParseError

T = TypeVar("T", bound=BaseModel)


def parse_json(text: str) -> dict[str, Any]:
    """Extract and parse JSON from LLM output."""
    text = text.strip()

    # Try direct parse
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

    raise ParseError(f"Could not parse JSON from: {text[:200]}...")


def parse_model(text: str, model: type[T]) -> T:
    """Parse LLM output into a Pydantic model."""
    data = parse_json(text)
    return model.model_validate(data)


class StructuredParser:
    """Parser for structured LLM outputs."""

    def __init__(self, model: type[BaseModel]) -> None:
        self.model = model

    def parse(self, text: str) -> BaseModel:
        return parse_model(text, self.model)  # type: ignore[return-value]
