"""Tests for output parsing."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output import StructuredParser, parse_json, parse_model


def test_parse_json_raw():
    assert parse_json('{"key": "value"}') == {"key": "value"}


def test_parse_json_codeblock():
    text = 'Here is the result:\n```json\n{"a": 1}\n```'
    assert parse_json(text) == {"a": 1}


def test_parse_json_embedded():
    text = 'The answer is {"x": 42} as shown.'
    assert parse_json(text) == {"x": 42}


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
    result = parser.parse('{"value": 10}')
    assert result.value == 10
