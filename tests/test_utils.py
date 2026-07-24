"""Tests for utilities."""

from devai.utils import (
    estimate_tokens,
    extract_code_blocks,
    extract_first_code_block,
    truncate_to_tokens,
)


def test_estimate_tokens():
    assert estimate_tokens("hello world") >= 1
    assert estimate_tokens("") == 1


def test_truncate_to_tokens():
    long_text = "a" * 1000
    result = truncate_to_tokens(long_text, 10)
    assert len(result) < len(long_text)
    assert result.endswith("...")


def test_truncate_short_text():
    text = "short"
    assert truncate_to_tokens(text, 100) == text


def test_extract_code_blocks():
    text = "Here:\n```python\ndef foo():\n    pass\n```\nDone."
    blocks = extract_code_blocks(text)
    assert len(blocks) == 1
    assert "def foo" in blocks[0]


def test_extract_code_blocks_language():
    text = "```python\nx=1\n```\n```js\ny=2\n```"
    blocks = extract_code_blocks(text, language="python")
    assert len(blocks) == 1
    assert "x=1" in blocks[0]


def test_extract_first_code_block():
    text = "No code here"
    assert extract_first_code_block(text) is None

    text2 = "```\nhello\n```"
    assert extract_first_code_block(text2) == "hello"
