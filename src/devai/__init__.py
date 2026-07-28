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
from devai.runtime import DevRuntime
from devai.sandbox import CodeSandbox, SandboxResult
from devai.schemas import (
    CodeIssue,
    CodeReviewResult,
    PerfIssue,
    PerfReviewResult,
    SecurityAuditResult,
    SecurityFinding,
)

__version__ = "1.6.0"
__all__ = [
    "Agent",
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
    "SecurityAuditResult",
    "SecurityFinding",
    "get_preset",
    "list_presets",
    "program_schema",
    "__version__",
]
