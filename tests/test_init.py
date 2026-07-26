"""Tests for package imports."""

import devai


def test_version():
    assert devai.__version__ == "0.3.0"


def test_public_api():
    assert hasattr(devai, "LLMClient")
    assert hasattr(devai, "MockLLMClient")
    assert hasattr(devai, "DevAIConfig")
    assert hasattr(devai, "Agent")
    assert hasattr(devai, "CoderAgent")
    assert hasattr(devai, "ToolRegistry")
    assert hasattr(devai, "PromptTemplate")
    assert hasattr(devai, "CODE_REVIEW")
    assert hasattr(devai, "RAGChain")
    assert hasattr(devai, "VectorStore")
    assert hasattr(devai, "ConversationMemory")
    assert hasattr(devai, "Chain")
    assert hasattr(devai, "parse_json")
