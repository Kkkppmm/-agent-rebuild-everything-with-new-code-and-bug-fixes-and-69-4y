"""DevAI — A Python AI library for developers and programmers."""

from devai.assistant import CodeAssistant
from devai.core.config import DevAIConfig
from devai.project import CodeProject

__version__ = "0.7.0"
__all__ = ["CodeAssistant", "CodeProject", "DevAIConfig", "__version__"]
