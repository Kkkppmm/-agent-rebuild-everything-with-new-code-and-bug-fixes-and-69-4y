"""Tests for text utilities."""

from devai.utils.text import estimate_tokens, truncate_to_tokens, extract_code_blocks


def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("hello world") >= 1


def test_truncate_to_tokens():
    long_text = "a" * 1000
    truncated = truncate_to_tokens(long_text, 10)
    assert len(truncated) < len(long_text)
    assert truncated.endswith("...")


def test_extract_code_blocks():
    text = "Here is code:\n```python\ndef f():\n    pass\n```\nAnd more."
    blocks = extract_code_blocks(text)
    assert len(blocks) == 1
    assert "def f" in blocks[0]


def test_extract_code_blocks_filtered():
    text = "```python\npy code\n```\n```js\njs code\n```"
    blocks = extract_code_blocks(text, language="python")
    assert len(blocks) == 1
    assert "py code" in blocks[0]
