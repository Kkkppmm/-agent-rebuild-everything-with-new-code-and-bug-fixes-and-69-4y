"""Tests for output parsers."""

import pytest
from pydantic import BaseModel
from devai.output.parser import parse_json, parse_model, StructuredParser
from devai.core.exceptions import ParseError


def test_parse_json_direct():
    assert parse_json('{"key": "value"}') == {"key": "value"}


def test_parse_json_codeblock():
    text = "Here is the result:\n```json\n{\"a\": 1}\n```"
    assert parse_json(text) == {"a": 1}


def test_parse_json_embedded():
    text = "The answer is {\"score\": 10} as shown."
    result = parse_json(text)
    assert result["score"] == 10


def test_parse_json_failure():
    with pytest.raises(ParseError):
        parse_json("no json here at all")


def test_parse_model():
    class Item(BaseModel):
        name: str
        count: int

    result = parse_model('{"name": "test", "count": 3}', Item)
    assert result.name == "test"
    assert result.count == 3


def test_structured_parser():
    class Data(BaseModel):
        x: int

    parser = StructuredParser(Data)
    assert parser.parse('{"x": 42}').x == 42
    assert parser.parse_optional("invalid") is None
