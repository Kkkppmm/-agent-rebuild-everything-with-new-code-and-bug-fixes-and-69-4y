"""DevAI — A Python AI library for developers and programmers."""

from devai.agents import Agent, CoderAgent
from devai.assistant import CodeAssistant
from devai.core import BatchRunner, DevAIConfig, LLMClient, MockLLMClient
from devai.pipeline import DevPipeline
from devai.program import DevProgram, ProgramResult, ProgramTask
from devai.project import CodeProject
from devai.schemas import (
    CodeIssue,
    CodeReviewResult,
    PerfIssue,
    PerfReviewResult,
    SecurityAuditResult,
    SecurityFinding,
)

__version__ = "1.0.0"
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
    "DevProgram",
    "LLMClient",
    "MockLLMClient",
    "PerfIssue",
    "PerfReviewResult",
    "ProgramResult",
    "ProgramTask",
    "SecurityAuditResult",
    "SecurityFinding",
    "__version__",
]
