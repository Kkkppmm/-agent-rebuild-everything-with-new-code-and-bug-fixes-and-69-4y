"""DevAI — A Python AI library for developers and programmers."""

from devai.agents import Agent, CoderAgent
from devai.assistant import CodeAssistant
from devai.core import BatchRunner, DevAIConfig, LLMClient, MockLLMClient
from devai.pipeline import DevPipeline
from devai.project import CodeProject

__version__ = "0.8.0"
__all__ = [
    "Agent",
    "BatchRunner",
    "CodeAssistant",
    "CodeProject",
    "CoderAgent",
    "DevAIConfig",
    "DevPipeline",
    "LLMClient",
    "MockLLMClient",
    "__version__",
]
