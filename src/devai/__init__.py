"""DevAI — a lightweight Python AI library for developers."""

from devai.client import DevAI
from devai.exceptions import DevAIError, ProviderError, RateLimitError
from devai.types import (
    ChatResponse,
    EmbeddingResponse,
    Message,
    Role,
    StreamChunk,
    ToolCall,
    ToolDefinition,
)

__version__ = "0.1.0"
__all__ = [
    "DevAI",
    "DevAIError",
    "ProviderError",
    "RateLimitError",
    "ChatResponse",
    "EmbeddingResponse",
    "Message",
    "Role",
    "StreamChunk",
    "ToolCall",
    "ToolDefinition",
]
