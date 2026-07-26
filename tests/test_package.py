"""Tests for package imports."""

import devai


def test_version():
    assert devai.__version__ == "0.3.0"


def test_public_api():
    assert hasattr(devai, "LLMClient")
    assert hasattr(devai, "MockLLMClient")
    assert hasattr(devai, "CoderAgent")
    assert hasattr(devai, "RAGChain")
