"""Tests for utility functions."""

from devai.utils.text import estimate_tokens, extract_code_blocks, truncate_to_tokens


def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("hello world") >= 1


def test_truncate_to_tokens():
    long_text = "a" * 1000
    truncated = truncate_to_tokens(long_text, 10)
    assert len(truncated) < len(long_text)
    assert "truncated" in truncated


def test_extract_code_blocks():
    text = "Here is code:\n```python\nprint('hi')\n```\nAnd more:\n```\nfoo()\n```"
    blocks = extract_code_blocks(text)
    assert len(blocks) == 2
    assert "print('hi')" in blocks[0]
    assert "foo()" in blocks[1]
