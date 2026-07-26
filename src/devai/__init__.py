"""DevAI — A Python AI library for developers and programmers."""

from devai.core.config import DevAIConfig
from devai.core.client import LLMClient, MockLLMClient, EmbeddingClient
from devai.core.models import Message, ToolCall, ToolDefinition, LLMResponse

__version__ = "0.4.0"

__all__ = [
    "DevAIConfig",
    "LLMClient",
    "MockLLMClient",
    "EmbeddingClient",
    "Message",
    "ToolCall",
    "ToolDefinition",
    "LLMResponse",
    "__version__",
]
