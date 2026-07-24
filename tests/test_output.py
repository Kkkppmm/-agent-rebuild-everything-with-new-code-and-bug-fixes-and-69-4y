"""Tests for DevAI output parsers."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output import StructuredParser, parse_json, parse_model


def test_parse_json_raw():
    result = parse_json('{"key": "value"}')
    assert result == {"key": "value"}


def test_parse_json_codeblock():
    text = 'Here is the result:\n```json\n{"score": 10}\n```'
    result = parse_json(text)
    assert result["score"] == 10


def test_parse_json_no_json():
    with pytest.raises(ParseError):
        parse_json("no json here")


def test_parse_model():
    class Item(BaseModel):
        name: str
        count: int

    result = parse_model('{"name": "test", "count": 5}', Item)
    assert result.name == "test"
    assert result.count == 5


def test_structured_parser():
    class Result(BaseModel):
        answer: str

    parser = StructuredParser(Result)
    result = parser.parse('{"answer": "yes"}')
    assert result.answer == "yes"
