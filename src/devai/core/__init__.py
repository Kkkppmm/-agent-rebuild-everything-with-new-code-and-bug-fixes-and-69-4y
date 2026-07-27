"""Core primitives for DevAI."""

from devai.core.client import EmbeddingClient, LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.exceptions import (
    AuthenticationError,
    ConfigurationError,
    DevAIError,
    ProviderError,
    RateLimitError,
)
from devai.core.models import CompletionResult, Message, Role, ToolCall, ToolDefinition

__all__ = [
    "AuthenticationError",
    "CompletionResult",
    "ConfigurationError",
    "DevAIConfig",
    "DevAIError",
    "EmbeddingClient",
    "LLMClient",
    "Message",
    "MockLLMClient",
    "ProviderError",
    "RateLimitError",
    "Role",
    "ToolCall",
    "ToolDefinition",
]
