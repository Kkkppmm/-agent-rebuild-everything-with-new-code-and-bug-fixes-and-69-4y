"""DevAI — A Python AI library for developers and programmers."""

from devai.assistant import CodeAssistant
from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role, ToolCall, ToolDefinition

__version__ = "0.5.1"
__all__ = [
    "CodeAssistant",
    "DevAIConfig",
    "LLMClient",
    "Message",
    "MockLLMClient",
    "Role",
    "ToolCall",
    "ToolDefinition",
    "__version__",
]
