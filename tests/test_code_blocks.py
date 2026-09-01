"""Tests for code block extraction."""

from devai.output.code_blocks import (
    CodeBlock,
    extract_code_blocks,
    extract_code_by_language,
    extract_first_code_block,
)


SAMPLE = '''Here is the fix:

```python
def add(a, b):
    return a + b
```

And a shell command:

```bash
pip install devai
```

Plain text block:

```
no language tag
```
'''


class TestExtractCodeBlocks:
    def test_extract_multiple_blocks(self):
        blocks = extract_code_blocks(SAMPLE)
        assert len(blocks) == 3
        assert blocks[0].language == "python"
        assert "def add" in blocks[0].code
        assert blocks[1].language == "bash"
        assert blocks[2].language is None

    def test_block_positions(self):
        blocks = extract_code_blocks(SAMPLE)
        assert blocks[0].start < blocks[0].end
        assert SAMPLE[blocks[0].start : blocks[0].end].startswith("```python")

    def test_extract_first(self):
        code = extract_first_code_block(SAMPLE)
        assert code is not None
        assert "def add" in code

    def test_extract_first_by_language(self):
        code = extract_first_code_block(SAMPLE, language="bash")
        assert code is not None
        assert "pip install" in code

    def test_extract_first_missing_language(self):
        assert extract_first_code_block(SAMPLE, language="rust") is None

    def test_extract_by_language(self):
        grouped = extract_code_by_language(SAMPLE)
        assert "python" in grouped
        assert "bash" in grouped
        assert "text" in grouped

    def test_empty_text(self):
        assert extract_code_blocks("") == []

    def test_no_fences(self):
        assert extract_code_blocks("just plain text") == []

    def test_code_block_dataclass(self):
        block = CodeBlock(language="python", code="x = 1", start=0, end=10)
        assert block.language == "python"
        assert block.code == "x = 1"
