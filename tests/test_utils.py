"""Tests for utility functions."""

from devai.utils import estimate_tokens, extract_code_blocks, truncate_to_tokens


def test_estimate_tokens():
    assert estimate_tokens("hello world") >= 1
    assert estimate_tokens("") == 1


def test_extract_code_blocks():
    text = "Here is code:\n```python\nx = 1\n```\nDone."
    blocks = extract_code_blocks(text)
    assert len(blocks) == 1
    assert blocks[0] == ("python", "x = 1")


def test_truncate_to_tokens():
    text = "a" * 1000
    result = truncate_to_tokens(text, max_tokens=10)
    assert len(result) < len(text)
    assert result.endswith("...")
