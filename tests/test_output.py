"""Tests for output parsing."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output import StructuredParser, parse_json, parse_model


def test_parse_json_raw():
    assert parse_json('{"a": 1}') == {"a": 1}


def test_parse_json_fenced():
    text = '```json\n{"b": 2}\n```'
    assert parse_json(text) == {"b": 2}


def test_parse_json_invalid():
    with pytest.raises(ParseError):
        parse_json("not json at all")


def test_parse_model():
    class Item(BaseModel):
        name: str
        value: int

    result = parse_model('{"name": "test", "value": 42}', Item)
    assert result.name == "test"
    assert result.value == 42


def test_structured_parser():
    class Score(BaseModel):
        points: int

    parser = StructuredParser(Score)
    result = parser.parse('{"points": 10}')
    assert result.points == 10
