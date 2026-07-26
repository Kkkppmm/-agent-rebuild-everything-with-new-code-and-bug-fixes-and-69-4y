"""Tests for output parsing."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output import StructuredParser, parse_json, parse_model


def test_parse_json_plain():
    assert parse_json('{"a": 1}') == {"a": 1}


def test_parse_json_codeblock():
    text = 'Here is the result:\n```json\n{"key": "val"}\n```'
    assert parse_json(text) == {"key": "val"}


def test_parse_json_embedded():
    text = 'Some text {"nested": true} more text'
    assert parse_json(text) == {"nested": True}


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
    result = parser.parse({"name": "x", "value": 1})
    assert result.name == "x"


def test_structured_parser_from_string():
    parser = StructuredParser(Item)
    result = parser.parse('{"name": "y", "value": 2}')
    assert result.value == 2
