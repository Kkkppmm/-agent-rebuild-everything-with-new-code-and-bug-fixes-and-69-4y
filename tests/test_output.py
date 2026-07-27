"""Tests for DevAI output parsing."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output import StructuredParser, parse_json, parse_model


class TestParseJson:
    def test_direct_json(self):
        result = parse_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_json_in_code_block(self):
        text = 'Here is the result:\n```json\n{"score": 5}\n```'
        result = parse_json(text)
        assert result["score"] == 5

    def test_json_embedded(self):
        text = 'The answer is {"name": "test"} as shown.'
        result = parse_json(text)
        assert result["name"] == "test"

    def test_invalid_json(self):
        with pytest.raises(ParseError):
            parse_json("not json at all")


class TestStructuredParser:
    def test_parse_model(self):
        class Item(BaseModel):
            name: str
            count: int

        parser = StructuredParser(Item)
        result = parser.parse('{"name": "apple", "count": 3}')
        assert result.name == "apple"
        assert result.count == 3

    def test_parse_model_function(self):
        class Score(BaseModel):
            value: float

        result = parse_model('{"value": 9.5}', Score)
        assert result.value == 9.5
