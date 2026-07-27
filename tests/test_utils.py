"""Tests for utilities."""

from devai.utils.tokens import estimate_tokens, extract_code_blocks, truncate_to_tokens


def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("hello world") >= 1


def test_truncate_to_tokens():
    text = "a" * 1000
    result = truncate_to_tokens(text, 10)
    assert len(result) < len(text)
    assert result.endswith("...")


def test_truncate_short_text():
    text = "short"
    assert truncate_to_tokens(text, 100) == "short"


def test_extract_code_blocks():
    text = "Here is code:\n```python\ndef foo():\n    pass\n```\nDone."
    blocks = extract_code_blocks(text)
    assert len(blocks) == 1
    assert "def foo" in blocks[0]


def test_extract_code_blocks_with_language():
    text = "```python\nx = 1\n```\n```js\ny = 2\n```"
    blocks = extract_code_blocks(text, language="python")
    assert len(blocks) == 1
    assert "x = 1" in blocks[0]
