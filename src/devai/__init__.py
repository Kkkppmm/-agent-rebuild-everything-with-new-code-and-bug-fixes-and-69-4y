"""DevAI — A Python AI library for developers and programmers."""

from devai.core.config import DevAIConfig
from devai.core.client import LLMClient, MockLLMClient, EmbeddingClient
from devai.core.cache import CachedLLMClient
from devai.core.batch import BatchRunner, BatchRequest, BatchResult
from devai.core.models import Message, ToolCall, ToolDefinition, LLMResponse
from devai.assistant import CodeAssistant

__version__ = "0.6.0"

__all__ = [
    "DevAIConfig",
    "LLMClient",
    "MockLLMClient",
    "EmbeddingClient",
    "CachedLLMClient",
    "BatchRunner",
    "BatchRequest",
    "BatchResult",
    "Message",
    "ToolCall",
    "ToolDefinition",
    "LLMResponse",
    "CodeAssistant",
    "__version__",
]
