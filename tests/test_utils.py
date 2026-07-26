"""Tests for utility functions."""

from devai.utils import estimate_tokens, extract_code_blocks, truncate_to_tokens


class TestUtils:
    def test_estimate_tokens(self):
        assert estimate_tokens("hello world") >= 1

    def test_extract_code_blocks(self):
        text = "Here:\n```python\nx = 1\n```\nDone."
        blocks = extract_code_blocks(text, language="python")
        assert len(blocks) == 1
        assert "x = 1" in blocks[0]

    def test_extract_all_blocks(self):
        text = "```\ncode1\n```\n```\ncode2\n```"
        blocks = extract_code_blocks(text)
        assert len(blocks) == 2

    def test_truncate_to_tokens(self):
        text = "a" * 1000
        result = truncate_to_tokens(text, max_tokens=10)
        assert len(result) < len(text)
        assert result.endswith("...")

    def test_truncate_short_text(self):
        text = "short"
        assert truncate_to_tokens(text, max_tokens=100) == text
