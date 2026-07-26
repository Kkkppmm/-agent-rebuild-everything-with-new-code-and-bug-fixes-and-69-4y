"""Tests for package imports."""

import devai


def test_version():
    assert devai.__version__ == "0.3.0"


def test_public_api():
    expected = {
        "Agent", "Chain", "CoderAgent", "ConversationMemory",
        "DevAIConfig", "EmbeddingClient", "LLMClient", "Message",
        "MockLLMClient", "PromptTemplate", "RAGChain", "Role",
        "SequentialChain", "StructuredChain", "Tool", "ToolCall",
        "ToolRegistry", "VectorStore",
    }
    assert expected.issubset(set(devai.__all__))
