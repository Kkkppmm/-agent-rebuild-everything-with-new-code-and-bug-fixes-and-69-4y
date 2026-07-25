"""
DevAI — A lightweight Python AI library for developers.

Chat, stream, embed, tools, and agents with support for OpenAI, Anthropic, and Ollama.
"""

from devai.agents import Agent, AgentResult
from devai.chat import ChatSession
from devai.client import DevAI
from devai.embeddings import Embedder, cosine_similarity, euclidean_distance
from devai.exceptions import APIError, ConfigurationError, DevAIError, ToolExecutionError
from devai.memory import BufferMemory, Memory, WindowMemory
from devai.prompts import PromptTemplate, chain_prompts
from devai.tools import ToolRegistry, default_registry
from devai.types import (
  ChatResponse,
  EmbeddingResponse,
  Message,
  ProviderConfig,
  Role,
  StreamChunk,
  ToolCall,
  ToolDefinition,
)

__version__ = "0.1.0"

__all__ = [
  "__version__",
  "DevAI",
  "ChatSession",
  "Agent",
  "AgentResult",
  "Embedder",
  "ToolRegistry",
  "default_registry",
  "BufferMemory",
  "WindowMemory",
  "Memory",
  "PromptTemplate",
  "chain_prompts",
  "Message",
  "Role",
  "ChatResponse",
  "StreamChunk",
  "EmbeddingResponse",
  "ToolCall",
  "ToolDefinition",
  "ProviderConfig",
  "cosine_similarity",
  "euclidean_distance",
  "DevAIError",
  "APIError",
  "ConfigurationError",
  "ToolExecutionError",
]
