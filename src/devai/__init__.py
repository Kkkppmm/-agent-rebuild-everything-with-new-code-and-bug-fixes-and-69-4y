"""DevAI — A Python AI library for developers and programmers."""

from devai.agents import Agent, CoderAgent
from devai.assistant import CodeAssistant
from devai.core import BatchRunner, DevAIConfig, LLMClient, MockLLMClient
from devai.kit import DevKit
from devai.pipeline import DevPipeline
from devai.presets import get_preset, list_presets
from devai.program import DevProgram, ProgramResult, ProgramTask
from devai.project import CodeProject
from devai.ci import (
    CIAnnotation,
    ci_gate_passed,
    extract_annotations,
    format_actions_annotations,
    format_actions_summary,
    format_pr_comment,
    write_step_summary,
)
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
    "ci_gate_passed",
    "extract_annotations",
    "format_actions_annotations",
    "format_actions_summary",
    "format_pr_comment",
    "get_preset",
    "list_presets",
    "write_step_summary",
    "__version__",
]
