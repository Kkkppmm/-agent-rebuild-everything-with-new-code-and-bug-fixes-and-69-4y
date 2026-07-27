"""DevAI — A Python AI library for developers and programmers."""

from devai.agents import Agent, CoderAgent
from devai.assistant import CodeAssistant
from devai.core import BatchRunner, DevAIConfig, LLMClient, MockLLMClient
from devai.pipeline import DevPipeline
from devai.project import CodeProject
from devai.schemas import (
    CodeIssue,
    CodeReviewResult,
    PerfIssue,
    PerfReviewResult,
    SecurityAuditResult,
    SecurityFinding,
)

__version__ = "0.9.0"
__all__ = [
    "Agent",
    "BatchRunner",
    "CodeAssistant",
    "CodeIssue",
    "CodeProject",
    "CodeReviewResult",
    "CoderAgent",
    "DevAIConfig",
    "DevPipeline",
    "LLMClient",
    "MockLLMClient",
    "PerfIssue",
    "PerfReviewResult",
    "SecurityAuditResult",
    "SecurityFinding",
    "__version__",
]
