"""Structured output parsing."""

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
        data = parse_json(text)
        return self.model.model_validate(data)


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
            raise ParseError(f"Failed to parse JSON from code block: {exc}") from exc

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise ParseError(f"Failed to parse JSON object: {exc}") from exc

    raise ParseError("No valid JSON found in response")


def parse_model(text: str, model: type[T]) -> T:
    """Parse LLM text into a Pydantic model."""
    return StructuredParser(model).parse(text)
