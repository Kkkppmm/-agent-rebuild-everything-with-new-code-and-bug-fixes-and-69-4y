"""Tests for DevAI utils."""

from devai.utils import estimate_tokens, extract_code_blocks, truncate_to_tokens, strip_markdown


class TestEstimateTokens:
    def test_basic(self):
        tokens = estimate_tokens("hello world test")
        assert tokens > 0

    def test_empty(self):
        assert estimate_tokens("") == 0


class TestExtractCodeBlocks:
    def test_python_block(self):
        text = "Here is code:\n```python\ndef foo():\n    pass\n```"
        blocks = extract_code_blocks(text, language="python")
        assert len(blocks) == 1
        assert "def foo" in blocks[0]

    def test_multiple_blocks(self):
        text = "```\nblock1\n```\n```\nblock2\n```"
        blocks = extract_code_blocks(text)
        assert len(blocks) == 2


class TestTruncateToTokens:
    def test_short_text(self):
        text = "short text"
        assert truncate_to_tokens(text, 100) == text

    def test_long_text(self):
        text = "word " * 200
        result = truncate_to_tokens(text, 10)
        assert result.endswith("...")
        assert len(result) < len(text)


class TestStripMarkdown:
    def test_strip_formatting(self):
        text = "# Heading\n**bold** and *italic* and `code`"
        result = strip_markdown(text)
        assert "**" not in result
        assert "#" not in result
