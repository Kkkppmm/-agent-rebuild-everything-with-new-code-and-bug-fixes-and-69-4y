"""Parse structured output from LLM responses."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel

from devai.core.exceptions import ParseError

T = TypeVar("T", bound=BaseModel)


def parse_json(text: str) -> dict:
    """Extract and parse JSON from text, handling markdown code blocks."""
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
            return json.loads(match.group(1).strip())
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


def parse_model(text: str, model: type[T]) -> T:
    """Parse text into a Pydantic model."""
    data = parse_json(text)
    return model.model_validate(data)


class StructuredParser:
    """Parser for structured LLM output with a target Pydantic model."""

    def __init__(self, model: type[T]):
        self.model = model

    def parse(self, text: str) -> T:
        return parse_model(text, self.model)

    def get_format_instruction(self) -> str:
        schema = self.model.model_json_schema()
        return f"Respond with valid JSON matching this schema:\n{json.dumps(schema, indent=2)}"
