"""DevAI — A Python AI library for developers and programmers."""

from devai.agents import Agent, CoderAgent
from devai.batch_review import BatchReviewReport, BatchReviewer, FileReviewResult
from devai.app import DevApp
from devai.ci import CIReporter
from devai.assistant import CodeAssistant
from devai.core import BatchRunner, DevAIConfig, EmbeddingClient, FallbackLLMClient, LLMClient, MockEmbeddingClient, MockLLMClient
from devai.core import DiskCachedLLMClient, BudgetExceededError
from devai.kit import DevKit
from devai.pipeline import DevPipeline
from devai.plugins import PluginRegistry
from devai.presets import get_preset, list_presets
from devai.program import DevProgram, ProgramResult, ProgramStepPlan, ProgramTask
from devai.program_schema import program_schema
from devai.project import CodeProject
from devai.benchmark import BenchmarkResult, BenchmarkRunner, BenchmarkSample
from devai.config_file import CONFIG_FILENAMES, config_file_template, find_config_file, load_config_file
from devai.context import ContextSection, DevContext, PromptBuilder
from devai.git_context import GitContext
from devai.hooks import DevHooks, SUPPORTED_HOOKS
from devai.doctor import DevDoctor, DoctorResult, run_doctor
from devai.health import HealthChecker, HealthResult, check_health
from devai.report import ProgramReport
from devai.export import export_program, export_program_to_file
from devai.facade import DevAI
from devai.interpolate import interpolate, interpolate_context
from devai.library import ProgramEntry, ProgramLibrary
from devai.quickstart import assistant, quickstart
from devai.runtime import DevRuntime
from devai.trace import DevTrace, TraceEvent
from devai.schedule import DevSchedule, ScheduleResult, ScheduledJob, cron_matches, validate_cron
from devai.watch import DevWatcher, WatchEvent, WatchResult
from devai.utils import TokenBudget, BudgetSnapshot, BudgetedLLMClient, PatchResult, apply_unified_diff, extract_diff_from_text
from devai.sandbox import CodeSandbox, SandboxResult
from devai.workflow import DevWorkflow, WorkflowResult, WorkflowStepResult
from devai.output import CodeBlock, extract_code_blocks, extract_code_by_language, extract_first_code_block
from devai.stream import StreamCollector, StreamResult
from devai.schemas import (
    CodeIssue,
    CodeReviewResult,
    PerfIssue,
    PerfReviewResult,
    SecurityAuditResult,
    SecurityFinding,
)

__version__ = "2.9.0"
__all__ = [
    "Agent",
    "BudgetExceededError",
    "BudgetedLLMClient",
    "BudgetSnapshot",
    "BenchmarkResult",
    "BenchmarkRunner",
    "BenchmarkSample",
    "CONFIG_FILENAMES",
    "HealthChecker",
    "HealthResult",
    "BatchReviewReport",
    "BatchReviewer",
    "BatchRunner",
    "CodeBlock",
    "CIReporter",
    "CodeAssistant",
    "CodeIssue",
    "CodeProject",
    "ContextSection",
    "CodeReviewResult",
    "CodeSandbox",
    "CoderAgent",
    "DevAI",
    "DevAIConfig",
    "DevApp",
    "DevContext",
    "DevKit",
    "DevHooks",
    "DevDoctor",
    "SUPPORTED_HOOKS",
    "StreamCollector",
    "StreamResult",
    "DevPipeline",
    "DevProgram",
    "DevRuntime",
    "DoctorResult",
    "ProgramReport",
    "DevSchedule",
    "DevTrace",
    "DevWatcher",
    "DevWorkflow",
    "DiskCachedLLMClient",
    "GitContext",
    "EmbeddingClient",
    "extract_diff_from_text",
    "extract_code_blocks",
    "extract_code_by_language",
    "extract_first_code_block",
    "export_program",
    "FileReviewResult",
    "export_program_to_file",
    "FallbackLLMClient",
    "LLMClient",
    "MockEmbeddingClient",
    "MockLLMClient",
    "PatchResult",
    "PerfIssue",
    "PerfReviewResult",
    "PluginRegistry",
    "ProgramEntry",
    "ProgramLibrary",
    "PromptBuilder",
    "ProgramResult",
    "ProgramStepPlan",
    "ProgramTask",
    "SandboxResult",
    "ScheduleResult",
    "ScheduledJob",
    "SecurityAuditResult",
    "SecurityFinding",
    "TokenBudget",
    "TraceEvent",
    "WatchEvent",
    "WatchResult",
    "WorkflowResult",
    "WorkflowStepResult",
    "apply_unified_diff",
    "assistant",
    "check_health",
    "config_file_template",
    "cron_matches",
    "get_preset",
    "interpolate",
    "interpolate_context",
    "find_config_file",
    "list_presets",
    "load_config_file",
    "program_schema",
    "quickstart",
    "run_doctor",
    "validate_cron",
    "__version__",
]
