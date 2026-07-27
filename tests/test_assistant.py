"""Tests for CodeAssistant."""

from devai.assistant import CodeAssistant
from devai.core.client import MockLLMClient


def test_assistant_review():
  client = MockLLMClient(responses={"review": "No issues found."})
  assistant = CodeAssistant(client=client)
  result = assistant.review("def add(a, b): return a + b")
  assert "No issues" in result


def test_assistant_explain():
  client = MockLLMClient(responses={"explain": "This adds two numbers."})
  assistant = CodeAssistant(client=client)
  result = assistant.explain("def add(a, b): return a + b")
  assert "adds two numbers" in result


def test_assistant_debug():
  client = MockLLMClient(responses={"debug": "Index out of range."})
  assistant = CodeAssistant(client=client)
  result = assistant.debug("items[10]", "IndexError")
  assert "Index" in result


def test_assistant_full_review():
  client = MockLLMClient()
  assistant = CodeAssistant(client=client)
  results = assistant.full_review("x = 1")
  assert "review" in results
  assert "security" in results
  assert "tests" in results
