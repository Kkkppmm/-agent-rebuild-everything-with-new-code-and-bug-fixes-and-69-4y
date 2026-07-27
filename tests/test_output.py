"""Tests for output parsing."""

import pytest
from pydantic import BaseModel

from devai.output import StructuredParser, parse_json, parse_model


class Item(BaseModel):
  name: str
  value: int


def test_parse_json_plain():
  assert parse_json('{"key": "val"}') == {"key": "val"}


def test_parse_json_codeblock():
  text = 'Here is the result:\n```json\n{"name": "test", "value": 42}\n```'
  data = parse_json(text)
  assert data["name"] == "test"


def test_parse_model():
  result = parse_model('{"name": "foo", "value": 1}', Item)
  assert result.name == "foo"
  assert result.value == 1


def test_structured_parser():
  parser = StructuredParser(Item)
  result = parser.parse('{"name": "bar", "value": 2}')
  assert result.name == "bar"


def test_parse_json_invalid():
  with pytest.raises(ValueError):
    parse_json("not json at all")
