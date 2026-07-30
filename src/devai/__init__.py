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
from devai.project_detect import ProjectDetector, ProjectProfile
from devai.prompt_registry import PromptRegistry
from devai.benchmark import BenchmarkResult, BenchmarkRunner, BenchmarkSample
from devai.code_compare import CodeComparer, CompareResult
from devai.code_metrics import CodeMetrics, FunctionMetric, FileMetric, ProjectMetrics
from devai.coverage_report import CoverageReport, CoverageSummary, FileCoverage
from devai.composer import ProgramComposer
from devai.config_file import CONFIG_FILENAMES, config_file_template, find_config_file, load_config_file
from devai.context import ContextSection, DevContext, PromptBuilder
from devai.deps_parser import Dependency, DependencyParser
from devai.git_context import GitContext
from devai.hooks import DevHooks, SUPPORTED_HOOKS
from devai.doctor import DevDoctor, DoctorResult, run_doctor
from devai.health import HealthChecker, HealthResult, check_health
from devai.report import ProgramReport
from devai.export import export_program, export_program_to_file
from devai.facade import DevAI
from devai.git_changelog import CommitInfo, GitChangelog
from devai.import_graph import ImportEdge, ImportGraph
from devai.interpolate import interpolate, interpolate_context
from devai.library import ProgramEntry, ProgramLibrary
from devai.notebook import NotebookCell, NotebookReader
from devai.quickstart import assistant, quickstart
from devai.runtime import DevRuntime
from devai.trace import DevTrace, TraceEvent
from devai.schedule import DevSchedule, ScheduleResult, ScheduledJob, cron_matches, validate_cron
from devai.schedule_config import apply_schedule_config, load_schedule_config, schedule_from_config
from devai.watch import DevWatcher, WatchEvent, WatchResult
from devai.utils import TokenBudget, BudgetSnapshot, BudgetedLLMClient, PatchResult, apply_unified_diff, extract_diff_from_text
from devai.sandbox import CodeSandbox, SandboxResult
from devai.workflow import DevWorkflow, WorkflowResult, WorkflowStepResult
from devai.output import CodeBlock, extract_code_blocks, extract_code_by_language, extract_first_code_block
from devai.stream import StreamCollector, StreamResult
from devai.index import CodeSymbolIndex, SymbolInfo
from devai.secrets import SecretFinding, SecretsScanner
from devai.typing_coverage import TypingCoverage, TypingGap, TypingStats
from devai.schemas import (
    CodeIssue,
    CodeReviewResult,
    PerfIssue,
    PerfReviewResult,
    SecurityAuditResult,
    SecurityFinding,
)

__version__ = "3.6.0"
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
    "CommitInfo",
    "CIReporter",
    "CodeAssistant",
    "CodeBlock",
    "CodeComparer",
    "CodeMetrics",
    "CoverageReport",
    "CoverageSummary",
    "FileCoverage",
    "FileMetric",
    "FunctionMetric",
    "ProjectMetrics",
    "CodeIssue",
    "CodeProject",
    "CompareResult",
    "ContextSection",
    "CodeReviewResult",
    "CodeSandbox",
    "CodeSymbolIndex",
    "CoderAgent",
    "Dependency",
    "DependencyParser",
    "DevAI",
    "DevAIConfig",
    "DevApp",
    "DevContext",
    "DevKit",
    "DevHooks",
    "SUPPORTED_HOOKS",
    "StreamCollector",
    "StreamResult",
    "DevDoctor",
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
    "GitChangelog",
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
    "NotebookCell",
    "NotebookReader",
    "PatchResult",
    "PerfIssue",
    "PerfReviewResult",
    "PluginRegistry",
    "ProgramComposer",
    "ProgramEntry",
    "ProgramLibrary",
    "ProjectDetector",
    "ProjectProfile",
    "PromptRegistry",
    "apply_schedule_config",
    "load_schedule_config",
    "schedule_from_config",
    "PromptBuilder",
    "ProgramResult",
    "ProgramStepPlan",
    "ProgramTask",
    "SandboxResult",
    "ScheduleResult",
    "ScheduledJob",
    "SecretFinding",
    "SecretsScanner",
    "SecurityAuditResult",
    "SecurityFinding",
    "ImportEdge",
    "ImportGraph",
    "SymbolInfo",
    "TokenBudget",
    "TypingCoverage",
    "TypingGap",
    "TypingStats",
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
