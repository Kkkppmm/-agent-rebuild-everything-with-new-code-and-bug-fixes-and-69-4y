"""DevAI — A Python AI library for developers and programmers."""

from devai.agents import Agent, CoderAgent
from devai.app import DevApp
from devai.benchmark import BenchmarkResult, BenchmarkRunner, benchmark_mock
from devai.ci import CIReporter
from devai.assistant import CodeAssistant
from devai.config_file import config_file_template, find_config_file, load_config_file
from devai.core import BatchRunner, DevAIConfig, EmbeddingClient, LLMClient, MockEmbeddingClient, MockLLMClient
from devai.doctor import DevDoctor, DoctorCheck, DoctorResult, run_doctor
from devai.git_context import GitContext
from devai.health import HealthChecker, HealthResult, check_health
from devai.interpolate import interpolate, interpolate_dict
from devai.kit import DevKit
from devai.pipeline import DevPipeline
from devai.plugins import PluginRegistry
from devai.presets import get_preset, list_presets
from devai.program import DevProgram, ProgramResult, ProgramStepPlan, ProgramTask
from devai.program_schema import program_schema
from devai.project import CodeProject
from devai.quickstart import assistant, quickstart
from devai.report import ProgramReport
from devai.runtime import DevRuntime
from devai.schedule import DevSchedule, ScheduleResult, ScheduledJob, cron_matches, validate_cron
from devai.trace import DevTrace, TraceSpan
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

__version__ = "1.9.0"
__all__ = [
    "Agent",
    "BatchRunner",
    "BenchmarkResult",
    "BenchmarkRunner",
    "CIReporter",
    "CodeAssistant",
    "CodeIssue",
    "CodeProject",
    "CodeReviewResult",
    "CodeSandbox",
    "CoderAgent",
    "DevAIConfig",
    "DevApp",
    "DevDoctor",
    "DevKit",
    "DevPipeline",
    "DevProgram",
    "DevRuntime",
    "DevSchedule",
    "DevTrace",
    "DevWorkflow",
    "DoctorCheck",
    "DoctorResult",
    "EmbeddingClient",
    "GitContext",
    "HealthChecker",
    "HealthResult",
    "LLMClient",
    "MockEmbeddingClient",
    "MockLLMClient",
    "PerfIssue",
    "PerfReviewResult",
    "PluginRegistry",
    "ProgramReport",
    "ProgramResult",
    "ProgramStepPlan",
    "ProgramTask",
    "SandboxResult",
    "ScheduleResult",
    "ScheduledJob",
    "SecurityAuditResult",
    "SecurityFinding",
    "TraceSpan",
    "WorkflowResult",
    "WorkflowStepResult",
    "assistant",
    "benchmark_mock",
    "check_health",
    "config_file_template",
    "cron_matches",
    "find_config_file",
    "get_preset",
    "interpolate",
    "interpolate_dict",
    "list_presets",
    "load_config_file",
    "program_schema",
    "quickstart",
    "run_doctor",
    "validate_cron",
    "__version__",
]
