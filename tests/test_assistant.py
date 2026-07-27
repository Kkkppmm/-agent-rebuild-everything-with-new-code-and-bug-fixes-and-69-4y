"""Tests for CodeAssistant."""

from pathlib import Path

import pytest

from devai import CodeAssistant
from devai.core.config import DevAIConfig


@pytest.fixture
def assistant() -> CodeAssistant:
    return CodeAssistant.mock(responses=["Review: looks good.", "Security: no issues."])


def test_mock_factory() -> None:
    a = CodeAssistant.mock()
    assert a.review("def foo(): pass") == "Mock response"


def test_review(assistant: CodeAssistant) -> None:
    result = assistant.review("def foo(): pass")
    assert "Review" in result


def test_explain(assistant: CodeAssistant) -> None:
    result = assistant.explain("x = 1 + 2")
    assert isinstance(result, str)


def test_debug(assistant: CodeAssistant) -> None:
    result = assistant.debug("def foo(): pass", "NameError: foo not defined")
    assert isinstance(result, str)


def test_security_review(assistant: CodeAssistant) -> None:
    result = assistant.security_review("import os; os.system('ls')")
    assert isinstance(result, str)


def test_generate_tests(assistant: CodeAssistant) -> None:
    result = assistant.generate_tests("def add(a, b): return a + b")
    assert isinstance(result, str)


def test_full_review(assistant: CodeAssistant) -> None:
    results = assistant.full_review("def foo(): pass")
    assert "review" in results
    assert "security" in results


def test_full_review_with_tests(assistant: CodeAssistant) -> None:
    results = assistant.full_review("def foo(): pass", include_tests=True)
    assert "test" in results


def test_summary(assistant: CodeAssistant) -> None:
    assistant.review("def foo(): pass")
    summary = assistant.summary()
    assert "REVIEW" in summary


def test_review_file(tmp_path: Path, assistant: CodeAssistant) -> None:
    f = tmp_path / "sample.py"
    f.write_text("def hello(): return 'world'\n")
    result = assistant.review_file(f)
    assert isinstance(result, str)


def test_from_config_mock() -> None:
    config = DevAIConfig(provider="mock")
    a = CodeAssistant.from_config(config)
    assert a.review("x=1") == "Mock response"


def test_from_env() -> None:
    a = CodeAssistant.from_env(provider="mock")
    assert a.explain("pass") == "Mock response"
