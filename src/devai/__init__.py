"""DevAI — A Python AI library for developers and programmers."""

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.embeddings import EmbeddingClient, MockEmbeddingClient, cosine_similarity
from devai.core.mock import MockLLMClient
from devai.core.models import Message, Role, StreamChunk, Tool, ToolCall
from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.chains.chain import Chain, SequentialChain
from devai.chains.structured import StructuredChain
from devai.memory.conversation import ConversationMemory
from devai.prompts.template import PromptTemplate
from devai.tools.registry import ToolRegistry
from devai.output.parsers import StructuredParser, parse_json, parse_model
from devai.rag import RAGChain, VectorStore, chunk_text

__version__ = "0.3.0"
__all__ = [
    "LLMClient",
    "MockLLMClient",
    "EmbeddingClient",
    "MockEmbeddingClient",
    "cosine_similarity",
    "DevAIConfig",
    "Message",
    "Role",
    "StreamChunk",
    "Tool",
    "ToolCall",
    "Agent",
    "CoderAgent",
    "Chain",
    "SequentialChain",
    "StructuredChain",
    "ConversationMemory",
    "PromptTemplate",
    "ToolRegistry",
    "StructuredParser",
    "parse_json",
    "parse_model",
    "RAGChain",
    "VectorStore",
    "chunk_text",
    "__version__",
]
