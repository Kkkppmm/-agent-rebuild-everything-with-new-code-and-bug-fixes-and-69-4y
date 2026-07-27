"""DevAI — A Python AI library for developers and programmers."""

from devai.assistant import CodeAssistant
from devai.core.config import DevAIConfig
from devai.project import CodeProject
from devai.schemas import (
    CodeIssue,
    CodeReviewResult,
    PerfIssue,
    PerfReviewResult,
    SecurityAuditResult,
    SecurityFinding,
)

__version__ = "0.8.0"
__all__ = [
    "CodeAssistant",
    "CodeIssue",
    "CodeProject",
    "CodeReviewResult",
    "DevAIConfig",
    "PerfIssue",
    "PerfReviewResult",
    "SecurityAuditResult",
    "SecurityFinding",
    "__version__",
]
