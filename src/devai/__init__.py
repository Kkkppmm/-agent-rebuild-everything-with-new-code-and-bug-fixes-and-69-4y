"""DevAI — A Python AI library for developers and programmers."""

from devai.core.config import DevAIConfig
from devai.core.client import LLMClient, MockLLMClient, EmbeddingClient
from devai.core.models import Message, ToolCall, ToolDefinition, LLMResponse
from devai.assistant import CodeAssistant

__version__ = "0.5.1"

__all__ = [
    "DevAIConfig",
    "LLMClient",
    "MockLLMClient",
    "EmbeddingClient",
    "Message",
    "ToolCall",
    "ToolDefinition",
    "LLMResponse",
    "CodeAssistant",
    "__version__",
]
