"""Tests for package imports."""

import devai
from devai.agents import Agent, CoderAgent
from devai.chains import Chain, LLMChain
from devai.memory import ConversationMemory
from devai.prompts import CODE_REVIEW
from devai.rag import RAGChain


def test_version():
    assert devai.__version__ == "0.3.0"


def test_public_api():
    assert devai.LLMClient is not None
    assert devai.MockLLMClient is not None
    assert devai.DevAIConfig is not None
    assert devai.Message is not None
