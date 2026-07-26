"""DevAI — a Python AI library for developers and programmers."""

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.embeddings import EmbeddingClient
from devai.core.models import Message, Role, Tool, ToolCall

__version__ = "0.3.0"

__all__ = [
    "LLMClient",
    "MockLLMClient",
    "EmbeddingClient",
    "DevAIConfig",
    "Message",
    "Role",
    "Tool",
    "ToolCall",
    "__version__",
]
