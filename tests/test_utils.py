"""Tests for DevAI utilities."""

from devai.utils.helpers import estimate_tokens, truncate_to_tokens, extract_code_blocks


class TestHelpers:
    def test_estimate_tokens(self):
        assert estimate_tokens("") == 0
        assert estimate_tokens("hello world") > 0

    def test_truncate_to_tokens(self):
        text = "a" * 1000
        result = truncate_to_tokens(text, 10)
        assert len(result) < len(text)
        assert result.endswith("...")

    def test_truncate_short_text(self):
        assert truncate_to_tokens("short", 100) == "short"

    def test_extract_code_blocks(self):
        text = "Here is code:\n```python\nprint('hi')\n```\nAnd more:\n```js\nconsole.log(1)\n```"
        blocks = extract_code_blocks(text)
        assert len(blocks) == 2
        assert blocks[0].language == "python"
        assert "print" in blocks[0].code
        assert blocks[1].language == "js"

    def test_extract_no_blocks(self):
        assert extract_code_blocks("no code here") == []
