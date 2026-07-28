"""Tests for DevAI utilities."""

from devai.utils import estimate_cost, estimate_tokens, extract_code_blocks, truncate_to_tokens


class TestUtils:
    def test_estimate_tokens(self):
        assert estimate_tokens("hello world") > 0
        assert estimate_tokens("") == 1

    def test_extract_code_blocks(self):
        text = "Here is code:\n```python\ndef foo():\n    pass\n```\nDone."
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert "def foo" in blocks[0]

    def test_extract_code_blocks_with_language(self):
        text = "```python\nx = 1\n```\n```javascript\ny = 2\n```"
        blocks = extract_code_blocks(text, language="python")
        assert len(blocks) == 1
        assert "x = 1" in blocks[0]

    def test_truncate_to_tokens(self):
        long_text = "word " * 1000
        truncated = truncate_to_tokens(long_text, 10)
        assert len(truncated) < len(long_text)
        assert "truncated" in truncated

    def test_truncate_short_text(self):
        text = "short"
        assert truncate_to_tokens(text, 100) == text

    def test_estimate_cost(self):
        cost = estimate_cost(1000, 500, model="gpt-4o-mini")
        assert cost > 0
        assert isinstance(cost, float)

    def test_estimate_cost_unknown_model(self):
        cost = estimate_cost(1_000_000, 1_000_000, model="unknown-model")
        assert cost > 0
