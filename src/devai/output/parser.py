"""Structured output parsing."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel

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
    return json.loads(match.group(1))
  match = re.search(r"\{.*\}", text, re.DOTALL)
  if match:
    return json.loads(match.group(0))
  raise ValueError(f"Could not parse JSON from: {text[:200]}")


def parse_model(text: str, model: type[T]) -> T:
  """Parse LLM output into a Pydantic model."""
  data = parse_json(text)
  return model.model_validate(data)


class StructuredParser:
  """Parser for structured LLM outputs."""

  def __init__(self, model: type[T]) -> None:
    self.model = model

  def parse(self, text: str) -> T:
    return parse_model(text, self.model)
