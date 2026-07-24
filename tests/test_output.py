"""Tests for output parsing and utilities."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output.parser import StructuredParser, parse_json, parse_model
from devai.utils.text import estimate_tokens, extract_code_blocks, truncate_to_tokens


class Item(BaseModel):
    name: str
    value: int


class TestParseJson:
    def test_direct_json(self):
        assert parse_json('{"key": "value"}') == {"key": "value"}

    def test_code_block(self):
        text = 'Here is the result:\n```json\n{"a": 1}\n```'
        assert parse_json(text) == {"a": 1}

    def test_embedded_json(self):
        text = 'The answer is {"x": 42} as shown.'
        assert parse_json(text) == {"x": 42}

    def test_invalid_raises(self):
        with pytest.raises(ParseError):
            parse_json("not json at all")


class TestParseModel:
    def test_parse_model(self):
        result = parse_model('{"name": "test", "value": 42}', Item)
        assert result.name == "test"
        assert result.value == 42


class TestStructuredParser:
    def test_parse(self):
        parser = StructuredParser(Item)
        result = parser.parse('{"name": "foo", "value": 1}')
        assert isinstance(result, Item)


class TestTextUtils:
    def test_estimate_tokens(self):
        assert estimate_tokens("hello world") >= 1

    def test_truncate(self):
        text = "a" * 1000
        result = truncate_to_tokens(text, max_tokens=10)
        assert len(result) < len(text)

    def test_extract_code_blocks(self):
        text = "Here:\n```python\ndef foo():\n    pass\n```\nDone."
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert blocks[0]["language"] == "python"
        assert "def foo" in blocks[0]["code"]
