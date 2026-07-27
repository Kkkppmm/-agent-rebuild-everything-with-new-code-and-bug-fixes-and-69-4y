"""Structured output parsing for DevAI."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel

from devai.core.exceptions import ParseError

T = TypeVar("T", bound=BaseModel)


class StructuredParser:
    """Parse structured output from LLM responses."""

    def __init__(self, model: type[T]) -> None:
        self.model = model

    def parse(self, text: str) -> T:
        data = parse_json(text)
        return self.model.model_validate(data)


def parse_json(text: str) -> dict:
    """Extract and parse JSON from LLM response text."""
    text = text.strip()

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from code block
    match = re.search(r"```(?:json)?\n?(.*?)```", text, re.DOTALL)
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

    raise ParseError(f"Could not parse JSON from response: {text[:200]}...")


def parse_model(text: str, model: type[T]) -> T:
    """Parse LLM response into a Pydantic model."""
    return StructuredParser(model).parse(text)
