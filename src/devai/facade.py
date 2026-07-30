"""DevAI — primary developer-facing entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devai.assistant import CodeAssistant
from devai.code_compare import CodeComparer, CompareResult
from devai.code_metrics import CodeMetrics
from devai.docstring_coverage import DocstringCoverage
from devai.test_mapper import TestMapper
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

    @staticmethod
    def prompts() -> PromptRegistry:
        """Return the built-in and registered prompt template registry."""
        return PromptRegistry()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._runtime, name)
