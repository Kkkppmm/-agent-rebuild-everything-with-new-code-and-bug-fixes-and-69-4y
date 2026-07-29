"""DevAI — A Python AI library for developers and programmers."""

from devai.agents import Agent, CoderAgent
from devai.app import DevApp
from devai.ci import CIReporter
from devai.assistant import CodeAssistant
from devai.core import BatchRunner, DevAIConfig, EmbeddingClient, LLMClient, MockEmbeddingClient, MockLLMClient
from devai.kit import DevKit
from devai.pipeline import DevPipeline
from devai.plugins import PluginRegistry
from devai.presets import get_preset, list_presets
from devai.program import DevProgram, ProgramResult, ProgramStepPlan, ProgramTask
from devai.program_schema import program_schema
from devai.project import CodeProject
from devai.git_context import GitContext
from devai.health import HealthChecker, HealthResult, check_health
from devai.interpolate import interpolate, interpolate_context
from devai.quickstart import assistant, quickstart
from devai.runtime import DevRuntime
from devai.trace import DevTrace, TraceEvent
from devai.schedule import DevSchedule, ScheduleResult, ScheduledJob, cron_matches, validate_cron
from devai.workflow import DevWorkflow, WorkflowResult, WorkflowStepResult
from devai.sandbox import CodeSandbox, SandboxResult
from devai.schemas import (
    CodeIssue,
    CodeReviewResult,
    PerfIssue,
    PerfReviewResult,
    SecurityAuditResult,
    SecurityFinding,
)

__version__ = "2.0.0"
__all__ = [
    "Agent",
    "HealthChecker",
    "HealthResult",
    "BatchRunner",
    "CIReporter",
    "CodeAssistant",
    "CodeIssue",
    "CodeProject",
    "CodeReviewResult",
    "CodeSandbox",
    "CoderAgent",
    "DevAIConfig",
    "DevApp",
    "DevKit",
    "DevPipeline",
    "DevProgram",
    "DevRuntime",
    "DevSchedule",
    "DevTrace",
    "DevWorkflow",
    "GitContext",
    "EmbeddingClient",
    "LLMClient",
    "MockEmbeddingClient",
    "MockLLMClient",
    "PerfIssue",
    "PerfReviewResult",
    "PluginRegistry",
    "ProgramResult",
    "ProgramStepPlan",
    "ProgramTask",
    "SandboxResult",
    "ScheduleResult",
    "ScheduledJob",
    "SecurityAuditResult",
    "SecurityFinding",
    "TraceEvent",
    "WorkflowResult",
    "WorkflowStepResult",
    "assistant",
    "check_health",
    "cron_matches",
    "get_preset",
    "interpolate",
    "interpolate_context",
    "list_presets",
    "program_schema",
    "quickstart",
    "validate_cron",
    "__version__",
]
