"""DevAI — primary developer-facing entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devai.api_surface import APISurfaceAnalyzer
from devai.assistant import CodeAssistant
from devai.code_compare import CodeComparer, CompareResult
from devai.code_metrics import CodeMetrics
from devai.code_smells import CodeSmellDetector
from devai.complexity_hotspots import ComplexityHotspotAnalyzer
from devai.exception_analyzer import ExceptionHierarchyAnalyzer
from devai.import_graph import ImportGraph
from devai.module_coupling import ModuleCouplingAnalyzer
from devai.async_blocking import AsyncBlockingDetector
from devai.command_injection import CommandInjectionAnalyzer
from devai.dangerous_calls import DangerousCallsAnalyzer
from devai.debug_artifacts import DebugArtifactDetector
from devai.magic_numbers import MagicNumberDetector
from devai.insecure_random import InsecureRandomAnalyzer
from devai.log_injection import LogInjectionAnalyzer
from devai.path_traversal import PathTraversalAnalyzer
from devai.resource_leaks import ResourceLeakAnalyzer
from devai.secrets import SecretsScanner
from devai.security_scan import SecurityScanner
from devai.sql_injection import SQLInjectionAnalyzer
from devai.ssrf import SSRFAnalyzer
from devai.cors_misconfig import CorsMisconfigAnalyzer
from devai.insecure_cookies import InsecureCookieAnalyzer
from devai.insecure_tls import InsecureTLSAnalyzer
from devai.mass_assignment import MassAssignmentAnalyzer
from devai.xss_vulnerabilities import XssVulnerabilityAnalyzer
from devai.naming_conventions import NamingConventionAnalyzer
from devai.dead_code import DeadCodeAnalyzer
from devai.docstring_coverage import DocstringCoverage
from devai.duplicate_code import DuplicateCodeDetector
from devai.tech_debt import TechDebtScanner
from devai.test_mapper import TestMapper
from devai.weak_crypto import WeakCryptoAnalyzer
from devai.project_health import ProjectHealth
from devai.program import DevProgram, ProgramResult
from devai.project_detect import ProjectDetector, ProjectProfile
from devai.prompt_registry import PromptRegistry
from devai.runtime import DevRuntime
from devai.workflow import DevWorkflow, WorkflowResult


class DevAI:
    """Primary developer-facing API for DevAI.

    Wraps :class:`DevRuntime` with convenient class methods and delegates
    common assistant and program operations.

    Example::

        from devai import DevAI

        ai = DevAI.mock()
        print(ai.review("def add(a, b): return a + b"))
        ai.run("pre-commit")
    """

    def __init__(self, runtime: DevRuntime) -> None:
        self._runtime = runtime

    @classmethod
    def mock(cls, *, project_path: str | Path | None = None, **kwargs: Any) -> DevAI:
        """Create a DevAI instance with a mock LLM (no API key required)."""
        return cls(DevRuntime.create(use_mock=True, project_path=project_path, **kwargs))

    @classmethod
    def openai(
        cls,
        *,
        api_key: str | None = None,
        model: str | None = None,
        project_path: str | Path | None = None,
        **kwargs: Any,
    ) -> DevAI:
        """Create a DevAI instance backed by the OpenAI API."""
        return cls(
            DevRuntime.create(
                provider="openai",
                api_key=api_key,
                model=model,
                project_path=project_path,
                **kwargs,
            )
        )

    @classmethod
    def ollama(
        cls,
        *,
        model: str | None = None,
        base_url: str = "http://localhost:11434/v1",
        project_path: str | Path | None = None,
        **kwargs: Any,
    ) -> DevAI:
        """Create a DevAI instance backed by a local Ollama server."""
        return cls(
            DevRuntime.create(
                provider="ollama",
                model=model,
                base_url=base_url,
                project_path=project_path,
                **kwargs,
            )
        )

    @classmethod
    def from_project(
        cls,
        path: str | Path | None = None,
        *,
        use_mock: bool = False,
        **kwargs: Any,
    ) -> DevAI:
        """Bootstrap from a project directory and optional ``.devai.yaml`` config."""
        return cls(DevRuntime.from_project(path, use_mock=use_mock, **kwargs))

    @property
    def runtime(self) -> DevRuntime:
        """Underlying :class:`DevRuntime` for advanced usage."""
        return self._runtime

    @property
    def assistant(self) -> CodeAssistant:
        """The wired :class:`CodeAssistant`."""
        return self._runtime.assistant

    def review(self, code: str) -> str:
        """Review code for issues and improvements."""
        return self._runtime.review(code)

    async def areview(self, code: str) -> str:
        """Async code review."""
        return await self._runtime.assistant.areview(code)

    def explain(self, code: str) -> str:
        """Explain what code does."""
        return self._runtime.explain(code)

    async def aexplain(self, code: str) -> str:
        """Async code explanation."""
        from devai.core.models import Message
        from devai.prompts import EXPLAIN

        msgs = []
        if EXPLAIN.system:
            msgs.append(Message.system(EXPLAIN.system))
        msgs.append(Message.user(EXPLAIN.format(code=code)))
        return await self._runtime.assistant.client.acomplete(msgs)

    def generate(self, spec: str) -> str:
        """Generate code from a specification."""
        return self._runtime.generate(spec)

    def debug(self, code: str, error: str) -> str:
        """Debug code given an error message."""
        return self._runtime.assistant.debug(code, error)

    def refactor(self, code: str, goals: str = "improve readability") -> str:
        """Refactor code toward a stated goal."""
        return self._runtime.assistant.refactor(code, goals=goals)

    def run(
        self,
        program: DevProgram | str,
        context: dict[str, str] | None = None,
        *,
        trace: bool = False,
    ) -> list[ProgramResult]:
        """Run a program, preset, or program file."""
        return self._runtime.run(program, context, trace=trace)

    async def arun(
        self,
        program: DevProgram | str,
        context: dict[str, str] | None = None,
        *,
        trace: bool = False,
    ) -> list[ProgramResult]:
        """Run a program asynchronously."""
        return await self._runtime.arun(program, context, trace=trace)

    def dry_run(
        self,
        program: DevProgram | str,
        context: dict[str, str] | None = None,
    ) -> list:
        """Preview program steps without calling the LLM."""
        return self._runtime.dry_run(program, context)

    def preset(self, name: str) -> DevProgram:
        """Load a built-in program preset."""
        return self._runtime.preset(name)

    def workflow(self, name: str = "workflow") -> DevWorkflow:
        """Create a new workflow bound to this instance."""
        return self._runtime.workflow(name)

    def run_workflow(
        self,
        workflow: DevWorkflow,
        context: dict[str, str] | None = None,
    ) -> WorkflowResult:
        """Execute a workflow and return structured results."""
        return self._runtime.run_workflow(workflow, context)

    def review_git(self, *, staged: bool = False, base: str | None = None) -> str:
        """Review git changes in the project."""
        return self._runtime.review_git(staged=staged, base=base)

    def doctor(self, *, probe: bool = True) -> list:
        """Run environment diagnostics."""
        return self._runtime.doctor(probe=probe)

    def compare(
        self,
        before: str | Path,
        after: str | Path,
        *,
        review: bool = False,
        before_label: str | None = None,
        after_label: str | None = None,
    ) -> CompareResult | str:
        """Compare two code sources. Set ``review=True`` for an AI review of changes."""
        comparer = CodeComparer(self._runtime.assistant)
        if review:
            return comparer.review_changes(
                before, after, before_label=before_label, after_label=after_label
            )
        return comparer.compare(before, after, before_label=before_label, after_label=after_label)

    def detect_project(self, path: str | Path = ".") -> ProjectProfile:
        """Detect project language, framework, and tooling from a directory."""
        return ProjectDetector().detect(path)

    def metrics(self, path: str | Path = ".", **kwargs: Any) -> CodeMetrics:
        """Analyze static code metrics (complexity, LOC, function counts) for a project."""
        return CodeMetrics(str(path), **kwargs)

    def docstrings(self, path: str | Path = ".", **kwargs: Any) -> DocstringCoverage:
        """Analyze docstring coverage for functions, methods, and classes."""
        return DocstringCoverage(str(path), **kwargs)

    def test_map(self, path: str | Path = ".", **kwargs: Any) -> TestMapper:
        """Map source modules to test files and find untested modules."""
        return TestMapper(str(path), **kwargs)

    def health(self, path: str | Path = ".", **kwargs: Any) -> ProjectHealth:
        """Run unified project health analysis (metrics, typing, tests, deps, secrets)."""
        return ProjectHealth(str(path), **kwargs)

    def smells(self, path: str | Path = ".", **kwargs: Any) -> CodeSmellDetector:
        """Detect code smells (long functions, deep nesting, bare except, god classes)."""
        return CodeSmellDetector(str(path), **kwargs)

    def tech_debt(self, path: str | Path = ".", **kwargs: Any) -> TechDebtScanner:
        """Scan for TODO, FIXME, HACK, and other tech-debt comment markers."""
        return TechDebtScanner(str(path), **kwargs)

    def duplicates(self, path: str | Path = ".", **kwargs: Any) -> DuplicateCodeDetector:
        """Find duplicate and near-duplicate code blocks across the project."""
        return DuplicateCodeDetector(str(path), **kwargs)

    def dead_code(self, path: str | Path = ".", **kwargs: Any) -> DeadCodeAnalyzer:
        """Find potentially unused top-level Python functions and classes."""
        return DeadCodeAnalyzer(str(path), **kwargs)

    def api_surface(self, path: str | Path = ".", **kwargs: Any) -> APISurfaceAnalyzer:
        """Map and analyze the public API surface of a Python package."""
        return APISurfaceAnalyzer(str(path), **kwargs)

    def hotspots(self, path: str | Path = ".", **kwargs: Any) -> ComplexityHotspotAnalyzer:
        """Rank files by complexity debt to prioritize refactoring."""
        return ComplexityHotspotAnalyzer(str(path), **kwargs)

    def imports(self, path: str | Path = ".", **kwargs: Any) -> ImportGraph:
        """Build and analyze Python import dependencies."""
        return ImportGraph(str(path), **kwargs)

    def exceptions(self, path: str | Path = ".", **kwargs: Any) -> ExceptionHierarchyAnalyzer:
        """Map custom exception classes and risky except handlers."""
        return ExceptionHierarchyAnalyzer(str(path), **kwargs)

    def coupling(self, path: str | Path = ".", **kwargs: Any) -> ModuleCouplingAnalyzer:
        """Measure module afferent/efferent coupling and instability."""
        return ModuleCouplingAnalyzer(str(path), **kwargs)

    def naming(self, path: str | Path = ".", **kwargs: Any) -> NamingConventionAnalyzer:
        """Check PEP 8 naming conventions for functions, classes, and variables."""
        return NamingConventionAnalyzer(str(path), **kwargs)

    def magic_numbers(self, path: str | Path = ".", **kwargs: Any) -> MagicNumberDetector:
        """Find unexplained numeric literals that should be named constants."""
        return MagicNumberDetector(str(path), **kwargs)

    def dangerous_calls(self, path: str | Path = ".", **kwargs: Any) -> DangerousCallsAnalyzer:
        """Detect risky calls (eval, exec, shell=True) and mutable default arguments."""
        return DangerousCallsAnalyzer(str(path), **kwargs)

    def secrets(self, path: str | Path = ".", **kwargs: Any) -> SecretsScanner:
        """Scan for hardcoded API keys, tokens, and credentials."""
        return SecretsScanner(str(path), **kwargs)

    def sql_injection(self, path: str | Path = ".", **kwargs: Any) -> SQLInjectionAnalyzer:
        """Detect dynamic SQL construction in database execute calls."""
        return SQLInjectionAnalyzer(str(path), **kwargs)

    def command_injection(self, path: str | Path = ".", **kwargs: Any) -> CommandInjectionAnalyzer:
        """Detect dynamic shell command construction in os/subprocess calls."""
        return CommandInjectionAnalyzer(str(path), **kwargs)

    def debug_artifacts(self, path: str | Path = ".", **kwargs: Any) -> DebugArtifactDetector:
        """Find print, breakpoint, and pdb debug code left in sources."""
        return DebugArtifactDetector(str(path), **kwargs)

    def async_blocking(self, path: str | Path = ".", **kwargs: Any) -> AsyncBlockingDetector:
        """Detect blocking calls inside async functions."""
        return AsyncBlockingDetector(str(path), **kwargs)

    def resource_leaks(self, path: str | Path = ".", **kwargs: Any) -> ResourceLeakAnalyzer:
        """Detect files, sockets, and connections opened without context managers."""
        return ResourceLeakAnalyzer(str(path), **kwargs)

    def insecure_random(self, path: str | Path = ".", **kwargs: Any) -> InsecureRandomAnalyzer:
        """Detect use of random module for security-sensitive values."""
        return InsecureRandomAnalyzer(str(path), **kwargs)

    def path_traversal(self, path: str | Path = ".", **kwargs: Any) -> PathTraversalAnalyzer:
        """Detect unsafe file path construction from user-controlled input."""
        return PathTraversalAnalyzer(str(path), **kwargs)

    def weak_crypto(self, path: str | Path = ".", **kwargs: Any) -> WeakCryptoAnalyzer:
        """Detect use of weak cryptographic algorithms (MD5, SHA1) for security."""
        return WeakCryptoAnalyzer(str(path), **kwargs)

    def log_injection(self, path: str | Path = ".", **kwargs: Any) -> LogInjectionAnalyzer:
        """Detect log injection risks from dynamic log message construction."""
        return LogInjectionAnalyzer(str(path), **kwargs)

    def ssrf(self, path: str | Path = ".", **kwargs: Any) -> SSRFAnalyzer:
        """Detect server-side request forgery risks in outbound HTTP calls."""
        return SSRFAnalyzer(str(path), **kwargs)

    def insecure_tls(self, path: str | Path = ".", **kwargs: Any) -> InsecureTLSAnalyzer:
        """Detect disabled TLS verification and weak SSL configuration."""
        return InsecureTLSAnalyzer(str(path), **kwargs)

    def xss_vulnerabilities(self, path: str | Path = ".", **kwargs: Any) -> XssVulnerabilityAnalyzer:
        """Detect cross-site scripting risks in web frameworks."""
        return XssVulnerabilityAnalyzer(str(path), **kwargs)

    def cors_misconfig(self, path: str | Path = ".", **kwargs: Any) -> CorsMisconfigAnalyzer:
        """Detect overly permissive CORS configuration."""
        return CorsMisconfigAnalyzer(str(path), **kwargs)

    def insecure_cookies(self, path: str | Path = ".", **kwargs: Any) -> InsecureCookieAnalyzer:
        """Detect cookies missing secure, httponly, or samesite flags."""
        return InsecureCookieAnalyzer(str(path), **kwargs)

    def mass_assignment(self, path: str | Path = ".", **kwargs: Any) -> MassAssignmentAnalyzer:
        """Detect ORM mass-assignment from request data."""
        return MassAssignmentAnalyzer(str(path), **kwargs)

    def security_scan(self, path: str | Path = ".", **kwargs: Any) -> SecurityScanner:
        """Run unified static security analysis (secrets, injections, dangerous calls)."""
        return SecurityScanner(str(path), **kwargs)

    @staticmethod
    def prompts() -> PromptRegistry:
        """Return the built-in and registered prompt template registry."""
        return PromptRegistry()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._runtime, name)
