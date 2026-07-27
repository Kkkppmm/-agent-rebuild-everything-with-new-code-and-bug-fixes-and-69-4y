"""Tests for utilities."""

from devai.utils import estimate_tokens, extract_code_blocks, truncate_to_tokens


def test_estimate_tokens():
    assert estimate_tokens("hello world") >= 1


def test_extract_code_blocks():
    text = "Here:\n```python\nprint('hi')\n```\nDone."
    blocks = extract_code_blocks(text)
    assert len(blocks) == 1
    assert "print" in blocks[0]


def test_extract_code_blocks_language():
    text = "```python\ncode\n```"
    blocks = extract_code_blocks(text, language="python")
    assert blocks == ["code\n"]


def test_truncate_to_tokens():
    long_text = "x" * 10000
    truncated = truncate_to_tokens(long_text, max_tokens=10)
    assert len(truncated) < len(long_text)
    assert "truncated" in truncated
