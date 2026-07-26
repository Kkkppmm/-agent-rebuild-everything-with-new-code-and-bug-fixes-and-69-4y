"""Tests for utilities."""

from devai.utils.tokens import estimate_tokens, extract_code_blocks, truncate_to_tokens


def test_estimate_tokens():
    assert estimate_tokens("hello") >= 1
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
    text = "Here:\n```python\nx = 1\n```\nDone"
    blocks = extract_code_blocks(text, "python")
    assert len(blocks) == 1
    assert "x = 1" in blocks[0]
