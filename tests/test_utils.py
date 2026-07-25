"""Tests for utility functions."""

from devai.utils.code import extract_code_blocks, extract_first_code_block, strip_code_fences
from devai.utils.tokens import estimate_tokens, truncate_to_tokens


def test_estimate_tokens():
  assert estimate_tokens("") == 0
  assert estimate_tokens("hello world") >= 1


def test_truncate_to_tokens():
  text = "a" * 1000
  result = truncate_to_tokens(text, 10)
  assert len(result) < len(text)
  assert result.endswith("...")


def test_extract_code_blocks():
  text = "Here is code:\n```python\nprint('hi')\n```\nAnd more:\n```js\nconsole.log(1)\n```"
  blocks = extract_code_blocks(text)
  assert len(blocks) == 2
  assert blocks[0].language == "python"
  assert "print('hi')" in blocks[0].code


def test_extract_first_code_block():
  text = "```python\nx = 1\n```"
  code = extract_first_code_block(text, language="python")
  assert code == "x = 1"


def test_strip_code_fences():
  text = "```python\nx = 1\n```"
  assert strip_code_fences(text) == "x = 1"
