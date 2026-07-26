"""Tests for output parsing."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output import StructuredParser, parse_json, parse_model


class TestParseJson:
    def test_plain_json(self):
        assert parse_json('{"a": 1}') == {"a": 1}

    def test_fenced_json(self):
        text = 'Here is the result:\n```json\n{"b": 2}\n```'
        assert parse_json(text) == {"b": 2}

    def test_invalid_json(self):
        with pytest.raises(ParseError):
            parse_json("not json")


class TestParseModel:
    def test_valid(self):
        class Item(BaseModel):
            name: str
            value: int

        result = parse_model('{"name": "test", "value": 42}', Item)
        assert result.name == "test"
        assert result.value == 42


class TestStructuredParser:
    def test_parse(self):
        class Score(BaseModel):
            score: float

        parser = StructuredParser(Score)
        result = parser.parse('{"score": 9.5}')
        assert result.score == 9.5
