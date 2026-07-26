"""Tests for output parsing."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output.parser import StructuredParser, parse_json, parse_model


def test_parse_json_direct():
    result = parse_json('{"key": "value"}')
    assert result["key"] == "value"


def test_parse_json_codeblock():
    text = 'Here is the result:\n```json\n{"a": 1}\n```'
    result = parse_json(text)
    assert result["a"] == 1


def test_parse_json_invalid():
    with pytest.raises(ParseError):
        parse_json("not json at all")


def test_parse_model():
    class Item(BaseModel):
        name: str
        count: int

    result = parse_model('{"name": "test", "count": 5}', Item)
    assert result.name == "test"
    assert result.count == 5


def test_structured_parser():
    class Score(BaseModel):
        value: int

    parser = StructuredParser(Score)
    result = parser.parse('{"value": 99}')
    assert result.value == 99
