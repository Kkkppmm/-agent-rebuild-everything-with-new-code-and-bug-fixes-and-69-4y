"""Tests for output parsing."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output import StructuredParser, parse_json, parse_model


class TestParseJson:
    def test_plain_json(self):
        assert parse_json('{"key": "value"}') == {"key": "value"}

    def test_code_block(self):
        text = 'Here is the result:\n```json\n{"a": 1}\n```'
        assert parse_json(text) == {"a": 1}

    def test_invalid_json(self):
        with pytest.raises(ParseError):
            parse_json("not json")


class TestParseModel:
    def test_valid_model(self):
        class Item(BaseModel):
            name: str
            count: int

        result = parse_model('{"name": "test", "count": 5}', Item)
        assert result.name == "test"
        assert result.count == 5


class TestStructuredParser:
    def test_parser(self):
        class Score(BaseModel):
            value: float

        parser = StructuredParser(Score)
        result = parser.parse('{"value": 9.5}')
        assert result.value == 9.5
        assert "schema" in parser.get_schema_prompt().lower()
