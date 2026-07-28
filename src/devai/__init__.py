"""DevAI — A Python AI library for developers and programmers."""

from devai.agents import Agent, CoderAgent
from devai.assistant import CodeAssistant
from devai.ci import CIReport, report_from_performance, report_from_program, report_from_review, report_from_security
from devai.core import BatchRunner, DevAIConfig, LLMClient, MockLLMClient
from devai.kit import DevKit
from devai.pipeline import DevPipeline
from devai.presets import get_preset, list_presets
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

__version__ = "1.2.0"
__all__ = [
    "Agent",
    "BatchRunner",
    "CIReport",
    "CodeAssistant",
    "CodeIssue",
    "CodeProject",
    "CodeReviewResult",
    "CoderAgent",
    "DevAIConfig",
    "DevKit",
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
    "get_preset",
    "list_presets",
    "report_from_performance",
    "report_from_program",
    "report_from_review",
    "report_from_security",
    "__version__",
]
