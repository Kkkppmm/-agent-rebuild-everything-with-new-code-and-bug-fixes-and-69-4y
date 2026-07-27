"""Tests for utils, memory, output, pipeline, and prompts."""

import pytest
from pydantic import BaseModel

from devai import CodeAssistant, MockLLMClient
from devai.core.exceptions import ParseError
from devai.memory import ConversationMemory
from devai.output import StructuredParser, parse_json, parse_model
from devai.pipeline import DevPipeline
from devai.prompts import CODE_REVIEW, DEBUG, PromptTemplate
from devai.utils import estimate_tokens, extract_code_blocks, truncate_to_tokens


def test_estimate_tokens():
  assert estimate_tokens("") == 0
  assert estimate_tokens("hello world") >= 1


def test_truncate_to_tokens():
  text = "a" * 1000
  truncated = truncate_to_tokens(text, 10)
  assert len(truncated) < len(text)
  assert "[truncated]" in truncated


def test_extract_code_blocks():
  text = "Here is code:\n```python\ndef foo(): pass\n```\nDone."
  blocks = extract_code_blocks(text)
  assert len(blocks) == 1
  assert "def foo" in blocks[0]


def test_conversation_memory():
  mem = ConversationMemory(max_messages=3)
  mem.add_user("hello")
  mem.add_assistant("hi")
  mem.add_user("how are you?")
  mem.add_assistant("good")
  assert len(mem) == 3
  assert mem.get_messages()[0].content == "hi"


def test_parse_json():
  assert parse_json('{"key": "value"}') == {"key": "value"}
  assert parse_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_parse_json_invalid():
  with pytest.raises(ParseError):
    parse_json("not json")


def test_parse_model():
  class Item(BaseModel):
    name: str
    count: int

  item = parse_model('{"name": "test", "count": 5}', Item)
  assert item.name == "test"
  assert item.count == 5


def test_structured_parser():
  class Score(BaseModel):
    value: int

  parser = StructuredParser(model=Score)
  result = parser.parse('{"value": 10}')
  assert result.value == 10


def test_prompt_template():
  tmpl = PromptTemplate("Hello $name, your code is $language")
  assert tmpl.format(name="dev", language="Python") == "Hello dev, your code is Python"


def test_builtin_prompts():
  prompt = CODE_REVIEW.format(code="x=1", language="python")
  assert "x=1" in prompt
  prompt = DEBUG.format(error="TypeError", code="x+1", language="python")
  assert "TypeError" in prompt


def test_dev_pipeline():
  client = MockLLMClient(responses=["review", "security", "tests"])
  assistant = CodeAssistant(client=client)
  pipeline = DevPipeline.from_assistant(assistant)
  results = pipeline.review_pipeline("def foo(): pass")
  assert set(results.keys()) == {"review", "security", "tests"}


def test_dev_pipeline_debug():
  client = MockLLMClient(responses=["debug fix", "refactored"])
  assistant = CodeAssistant(client=client)
  pipeline = DevPipeline(assistant)
  results = pipeline.debug_pipeline("Error", "bad code")
  assert "debug" in results
  assert "refactor" in results
