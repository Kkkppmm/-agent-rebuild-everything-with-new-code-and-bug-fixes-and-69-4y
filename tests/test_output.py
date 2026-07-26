"""Tests for output parsing."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output.parser import StructuredParser, parse_json, parse_model


def test_parse_json_direct():
    assert parse_json('{"key": "value"}') == {"key": "value"}


def test_parse_json_codeblock():
    text = 'Here is the result:\n```json\n{"score": 5}\n```'
    assert parse_json(text) == {"score": 5}


def test_parse_json_embedded():
    text = 'The answer is {"result": true} as shown.'
    assert parse_json(text) == {"result": True}


def test_parse_json_invalid():
    with pytest.raises(ParseError):
        parse_json("not json at all")


class Item(BaseModel):
    name: str
    value: int


def test_parse_model():
    result = parse_model('{"name": "test", "value": 42}', Item)
    assert result.name == "test"
    assert result.value == 42


def test_structured_parser():
    parser = StructuredParser(Item)
    result = parser.parse('{"name": "x", "value": 1}')
    assert result.name == "x"
    instruction = parser.get_format_instruction()
    assert "name" in instruction
