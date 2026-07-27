"""Structured output parsing."""

from __future__ import annotations

import json
from typing import TypeVar

from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.utils import extract_json_block

T = TypeVar("T", bound=BaseModel)


def parse_json(text: str) -> dict:
  """Parse JSON from LLM response text."""
  raw = extract_json_block(text) or text.strip()
  try:
    return json.loads(raw)
  except json.JSONDecodeError as e:
    raise ParseError(f"Failed to parse JSON: {e}") from e


def parse_model(text: str, model: type[T]) -> T:
  """Parse LLM response into a Pydantic model."""
  data = parse_json(text)
  try:
    return model.model_validate(data)
  except Exception as e:
    raise ParseError(f"Failed to validate model {model.__name__}: {e}") from e


class StructuredParser:
  """Parser for structured LLM outputs."""

  def __init__(self, model: type[BaseModel] | None = None) -> None:
    self.model = model

  def parse(self, text: str) -> dict | BaseModel:
    data = parse_json(text)
    if self.model:
      return self.model.model_validate(data)
    return data
