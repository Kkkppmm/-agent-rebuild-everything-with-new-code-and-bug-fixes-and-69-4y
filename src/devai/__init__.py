"""DevAI — A Python AI library for developers and programmers."""

from devai.assistant import CodeAssistant
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role, ToolCall, ToolDefinition

__version__ = "0.1.0"
__all__ = [
    "CodeAssistant",
    "DevAIConfig",
    "Message",
    "Role",
    "ToolCall",
    "ToolDefinition",
    "__version__",
]
