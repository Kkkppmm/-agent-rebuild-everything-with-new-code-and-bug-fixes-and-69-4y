"""DevAI — A Python AI library for developers and programmers."""

from devai.core.client import EmbeddingClient, LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role, Tool, ToolCall

__version__ = "0.3.0"
__all__ = [
    "DevAIConfig",
    "EmbeddingClient",
    "LLMClient",
    "Message",
    "MockLLMClient",
    "Role",
    "Tool",
    "ToolCall",
    "__version__",
]
