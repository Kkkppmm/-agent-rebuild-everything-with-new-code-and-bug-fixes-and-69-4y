"""DevAI — A Python AI library for developers and programmers."""

from devai.core.config import DevAIConfig
from devai.core.client import LLMClient, MockLLMClient, EmbeddingClient
from devai.core.models import Message, ToolCall, ToolDefinition, LLMResponse
from devai.pipeline import DevPipeline, PipelineResult

__version__ = "0.4.0"

__all__ = [
    "DevAIConfig",
    "DevPipeline",
    "EmbeddingClient",
    "LLMClient",
    "LLMResponse",
    "Message",
    "MockLLMClient",
    "PipelineResult",
    "ToolCall",
    "ToolDefinition",
    "__version__",
]
