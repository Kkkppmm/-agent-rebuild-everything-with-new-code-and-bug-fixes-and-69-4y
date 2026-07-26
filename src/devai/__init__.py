"""DevAI — A Python AI library for developers and programmers."""

from devai.core.client import EmbeddingClient, LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Response, ToolCall, ToolDefinition
from devai.core.exceptions import (
    DevAIError,
    APIError,
    RateLimitError,
    AuthenticationError,
    ConfigurationError,
)
from devai.prompts.templates import PromptTemplate
from devai.prompts.dev_prompts import (
    CODE_REVIEW,
    DEBUG,
    COMMIT_MESSAGE,
    API_DESIGN,
    SECURITY_REVIEW,
    SQL_OPTIMIZE,
    README_GEN,
    TYPE_HINTS,
    REGEX_BUILD,
    LOG_ANALYSIS,
    REFACTOR,
    EXPLAIN_CODE,
    GENERATE_TESTS,
)
from devai.tools.registry import ToolRegistry
from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.chains.chain import Chain, SequentialChain, StructuredChain
from devai.memory.conversation import ConversationMemory
from devai.rag.rag import RAGChain, VectorStore, chunk_text
from devai.output.parser import StructuredParser, parse_json, parse_model

__version__ = "0.3.0"

__all__ = [
    # Core
    "DevAIConfig",
    "LLMClient",
    "MockLLMClient",
    "EmbeddingClient",
    "Message",
    "Response",
    "ToolCall",
    "ToolDefinition",
    "DevAIError",
    "APIError",
    "RateLimitError",
    "AuthenticationError",
    "ConfigurationError",
    # Prompts
    "PromptTemplate",
    "CODE_REVIEW",
    "DEBUG",
    "COMMIT_MESSAGE",
    "API_DESIGN",
    "SECURITY_REVIEW",
    "SQL_OPTIMIZE",
    "README_GEN",
    "TYPE_HINTS",
    "REGEX_BUILD",
    "LOG_ANALYSIS",
    "REFACTOR",
    "EXPLAIN_CODE",
    "GENERATE_TESTS",
    # Tools
    "ToolRegistry",
    # Agents
    "Agent",
    "CoderAgent",
    # Chains
    "Chain",
    "SequentialChain",
    "StructuredChain",
    # Memory
    "ConversationMemory",
    # RAG
    "chunk_text",
    "VectorStore",
    "RAGChain",
    # Output
    "StructuredParser",
    "parse_json",
    "parse_model",
]
