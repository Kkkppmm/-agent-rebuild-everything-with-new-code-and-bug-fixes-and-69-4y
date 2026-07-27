"""Tests for DevAI output parsing."""

import pytest
from pydantic import BaseModel

from devai.output import StructuredParser, parse_json, parse_model
from devai.core.exceptions import ParseError


class TestParseJson:
    def test_direct_json(self):
        result = parse_json('{"key": "value"}')
        assert result["key"] == "value"

    def test_code_block(self):
        text = "Here is the result:\n```json\n{\"rating\": \"PASS\"}\n```"
        result = parse_json(text)
        assert result["rating"] == "PASS"

    def test_embedded_json(self):
        text = "The answer is {\"score\": 95} as shown."
        result = parse_json(text)
        assert result["score"] == 95

    def test_invalid(self):
        with pytest.raises(ParseError):
            parse_json("no json here at all")


class TestParseModel:
    def test_parse_model(self):
        class Result(BaseModel):
            name: str
            count: int

        result = parse_model('{"name": "test", "count": 42}', Result)
        assert result.name == "test"
        assert result.count == 42


class TestStructuredParser:
    def test_parse(self):
        class Item(BaseModel):
            title: str

        parser = StructuredParser(Item)
        result = parser.parse('{"title": "Hello"}')
        assert result.title == "Hello"

    def test_parse_safe(self):
        class Item(BaseModel):
            title: str

        parser = StructuredParser(Item)
        result = parser.parse_safe("not json")
        assert result is None
