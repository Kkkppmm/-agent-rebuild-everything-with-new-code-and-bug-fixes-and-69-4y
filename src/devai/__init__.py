"""DevAI — A Python AI library for developers and programmers."""

from devai.agents import Agent, CoderAgent
from devai.assistant import CodeAssistant
from devai.ci import (
    CIAnnotation,
    CIReport,
    merge_reports,
    report_from_performance_review,
    report_from_program_results,
    report_from_security_audit,
    report_from_structured_review,
)
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
    "CIAnnotation",
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
    "merge_reports",
    "report_from_performance_review",
    "report_from_program_results",
    "report_from_security_audit",
    "report_from_structured_review",
    "__version__",
]
