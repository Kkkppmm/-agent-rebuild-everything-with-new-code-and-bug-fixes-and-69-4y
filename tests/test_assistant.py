"""Tests for CodeAssistant."""

from devai import CodeAssistant, MockLLMClient

SAMPLE_CODE = "def add(a, b):\n    return a + b\n"


def test_review():
    assistant = CodeAssistant(client=MockLLMClient())
    result = assistant.review(SAMPLE_CODE)
    assert isinstance(result, str)
    assert len(result) > 0


def test_explain():
    assistant = CodeAssistant(client=MockLLMClient())
    result = assistant.explain(SAMPLE_CODE)
    assert isinstance(result, str)


def test_debug():
    assistant = CodeAssistant(client=MockLLMClient())
    result = assistant.debug(SAMPLE_CODE, error="TypeError")
    assert isinstance(result, str)


def test_refactor():
    assistant = CodeAssistant(client=MockLLMClient())
    result = assistant.refactor(SAMPLE_CODE)
    assert isinstance(result, str)


def test_security_review():
    assistant = CodeAssistant(client=MockLLMClient())
    result = assistant.security_review(SAMPLE_CODE)
    assert isinstance(result, str)


def test_generate_tests():
    assistant = CodeAssistant(client=MockLLMClient())
    result = assistant.generate_tests(SAMPLE_CODE)
    assert isinstance(result, str)


def test_commit_message():
    assistant = CodeAssistant(client=MockLLMClient())
    result = assistant.commit_message("diff --git a/foo.py")
    assert isinstance(result, str)


def test_full_review():
    assistant = CodeAssistant(client=MockLLMClient())
    result = assistant.full_review(SAMPLE_CODE)
    assert "review" in result
    assert "security" in result
    assert "tests" in result


def test_ask():
    assistant = CodeAssistant(client=MockLLMClient())
    result = assistant.ask("What is a list comprehension?")
    assert isinstance(result, str)
