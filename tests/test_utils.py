"""Tests for utility functions."""

from devai.utils import estimate_tokens, extract_code_blocks, strip_code_fences, truncate_to_tokens


class TestEstimateTokens:
    def test_basic(self):
        assert estimate_tokens("hello world") >= 1

    def test_long_text(self):
        text = "a" * 400
        assert estimate_tokens(text) == 100


class TestTruncateToTokens:
    def test_no_truncation(self):
        assert truncate_to_tokens("short", 100) == "short"

    def test_truncation(self):
        text = "a" * 1000
        result = truncate_to_tokens(text, 10)
        assert len(result) < len(text)
        assert result.endswith("...")


class TestExtractCodeBlocks:
    def test_single_block(self):
        text = "Here:\n```python\nprint(1)\n```"
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert "print(1)" in blocks[0]

    def test_language_filter(self):
        text = "```python\nx=1\n```\n```js\ny=2\n```"
        blocks = extract_code_blocks(text, language="python")
        assert len(blocks) == 1


class TestStripCodeFences:
    def test_strip(self):
        text = "```python\nprint(1)\n```"
        assert strip_code_fences(text) == "print(1)"
