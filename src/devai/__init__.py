"""DevAI — A Python AI library for developers and programmers."""

from devai.assistant import CodeAssistant
from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.pipeline import DevPipeline

__version__ = "0.1.0"
__all__ = [
    "CodeAssistant",
    "DevAIConfig",
    "DevPipeline",
    "LLMClient",
    "MockLLMClient",
    "__version__",
]
