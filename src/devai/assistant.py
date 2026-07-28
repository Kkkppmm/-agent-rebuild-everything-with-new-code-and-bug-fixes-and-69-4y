"""High-level CodeAssistant facade for DevAI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devai.chains import SimpleChain, StructuredChain
from devai.core.client import LLMClient, LLMClientProtocol
from devai.core.config import DevAIConfig
from devai.core.models import Message
from devai.prompts import (
    API_DESIGN,
    ARCHITECTURE,
    CHANGELOG,
    CODE_GEN,
    CODE_REVIEW,
    CODE_SMELL,
    CODE_TRANSLATE,
    COMMIT_MESSAGE,
    DEBUG,
    DEP_AUDIT,
    DIFF_REVIEW,
    DOCKERFILE_REVIEW,
    DOCSTRING_GEN,
    ERROR_HANDLER,
    EXPLAIN,
    FIX_LINT,
    LOG_ANALYSIS,
    MIGRATION_PLAN,
    OPENAPI_GEN,
    PERFORMANCE_REVIEW,
    PR_DESCRIPTION,
    README_GEN,
    REFACTOR,
    REGEX_BUILD,
    SECURITY_REVIEW,
    SQL_OPTIMIZE,
    STRUCTURED_PERFORMANCE,
    STRUCTURED_REVIEW,
    STRUCTURED_SECURITY,
    TEST_GEN,
    TYPE_HINTS,
)
from devai.schemas import CodeReviewResult, PerfReviewResult, SecurityAuditResult


class CodeAssistant:
    """High-level facade for developer-focused AI tasks."""

    def __init__(
        self,
        config: DevAIConfig | None = None,
        client: LLMClientProtocol | None = None,
        **kwargs: Any,
    ) -> None:
        if client is not None:
            self.client = client
        elif config is not None:
            self.client = LLMClient(config)
        else:
            self.client = LLMClient(DevAIConfig(**kwargs))

    def _run_chain(self, prompt_template: Any, **kwargs: Any) -> str:
        chain = SimpleChain(self.client, prompt_template)
        return chain.run(**kwargs)

    def review(self, code: str) -> str:
        """Review code for issues and improvements."""
        return self._run_chain(CODE_REVIEW, code=code)

    def explain(self, code: str) -> str:
        """Explain what code does."""
        return self._run_chain(EXPLAIN, code=code)

    def debug(self, code: str, error: str) -> str:
        """Debug code given an error message."""
        return self._run_chain(DEBUG, code=code, error=error)

    def refactor(self, code: str, goals: str = "improve readability and maintainability") -> str:
        """Refactor code with specified goals."""
        return self._run_chain(REFACTOR, code=code, goals=goals)

    def security(self, code: str) -> str:
        """Perform a security review of code."""
        return self._run_chain(SECURITY_REVIEW, code=code)

    def tests(self, code: str, framework: str = "pytest") -> str:
        """Generate unit tests for code."""
        return self._run_chain(TEST_GEN, code=code, framework=framework)

    def docstring(self, code: str) -> str:
        """Generate docstrings for code."""
        return self._run_chain(DOCSTRING_GEN, code=code)

    def commit_message(self, diff: str) -> str:
        """Generate a commit message from a diff."""
        return self._run_chain(COMMIT_MESSAGE, diff=diff)

    def pr_description(self, title: str, diff: str) -> str:
        """Generate a pull request description."""
        return self._run_chain(PR_DESCRIPTION, title=title, diff=diff)

    def changelog(self, version: str, changes: str) -> str:
        """Generate a changelog entry."""
        return self._run_chain(CHANGELOG, version=version, changes=changes)

    def translate_code(self, code: str, source_lang: str, target_lang: str) -> str:
        """Translate code between programming languages."""
        return self._run_chain(
            CODE_TRANSLATE, code=code, source_lang=source_lang, target_lang=target_lang
        )

    def add_error_handling(self, code: str) -> str:
        """Add error handling to code."""
        return self._run_chain(ERROR_HANDLER, code=code)

    def api_design(self, code: str, context: str = "") -> str:
        """Review and improve API design."""
        return self._run_chain(API_DESIGN, code=code, context=context)

    def optimize_sql(self, query: str, context: str = "") -> str:
        """Optimize a SQL query."""
        return self._run_chain(SQL_OPTIMIZE, query=query, context=context)

    def readme(self, project: str, description: str) -> str:
        """Generate a README for a project."""
        return self._run_chain(README_GEN, project=project, description=description)

    def type_hints(self, code: str) -> str:
        """Add Python type hints to code."""
        return self._run_chain(TYPE_HINTS, code=code)

    def regex(self, description: str, test_cases: str = "") -> str:
        """Build a regular expression from a description."""
        return self._run_chain(REGEX_BUILD, description=description, test_cases=test_cases)

    def analyze_logs(self, logs: str) -> str:
        """Analyze log output for errors and patterns."""
        return self._run_chain(LOG_ANALYSIS, logs=logs)

    def review_diff(self, diff: str) -> str:
        """Review a git diff for regressions and risky changes."""
        return self._run_chain(DIFF_REVIEW, diff=diff)

    def performance(self, code: str, context: str = "") -> str:
        """Analyze code for performance issues."""
        return self._run_chain(PERFORMANCE_REVIEW, code=code, context=context)

    def dockerfile(self, dockerfile: str) -> str:
        """Review a Dockerfile for security and best practices."""
        return self._run_chain(DOCKERFILE_REVIEW, dockerfile=dockerfile)

    def migration_plan(
        self,
        code: str,
        source: str,
        target: str,
        constraints: str = "",
    ) -> str:
        """Generate a migration plan between technologies or versions."""
        return self._run_chain(
            MIGRATION_PLAN,
            code=code,
            source=source,
            target=target,
            constraints=constraints,
        )

    def generate(self, spec: str, language: str = "python") -> str:
        """Generate code from a natural-language specification."""
        return self._run_chain(CODE_GEN, spec=spec, language=language)

    def fix_lint(self, code: str, lint_output: str) -> str:
        """Fix linter issues while preserving behavior."""
        return self._run_chain(FIX_LINT, code=code, lint_output=lint_output)

    def audit_deps(self, dependencies: str, context: str = "") -> str:
        """Audit project dependencies for security and licensing."""
        return self._run_chain(DEP_AUDIT, dependencies=dependencies, context=context)

    def architecture(self, code: str, context: str = "") -> str:
        """Describe codebase architecture with optional Mermaid diagram."""
        return self._run_chain(ARCHITECTURE, code=code, context=context)

    def openapi(self, code: str, context: str = "") -> str:
        """Generate an OpenAPI 3.0 specification from API code or description."""
        return self._run_chain(OPENAPI_GEN, code=code, context=context)

    def code_smell(
        self,
        code: str,
        focus: str = "readability, coupling, complexity, duplication",
    ) -> str:
        """Identify code smells and anti-patterns with refactoring suggestions."""
        return self._run_chain(CODE_SMELL, code=code, focus=focus)

    def structured_review(self, code: str) -> CodeReviewResult:
        """Return a structured code review as a Pydantic model."""
        chain = StructuredChain(self.client, STRUCTURED_REVIEW, CodeReviewResult)
        return chain.run(code=code)

    def structured_security(self, code: str) -> SecurityAuditResult:
        """Return a structured security audit as a Pydantic model."""
        chain = StructuredChain(self.client, STRUCTURED_SECURITY, SecurityAuditResult)
        return chain.run(code=code)

    def structured_performance(self, code: str, context: str = "") -> PerfReviewResult:
        """Return a structured performance review as a Pydantic model."""
        chain = StructuredChain(self.client, STRUCTURED_PERFORMANCE, PerfReviewResult)
        return chain.run(code=code, context=context)

    async def astructured_review(self, code: str) -> CodeReviewResult:
        """Async structured code review."""
        chain = StructuredChain(self.client, STRUCTURED_REVIEW, CodeReviewResult)
        return await chain.arun(code=code)

    async def astructured_security(self, code: str) -> SecurityAuditResult:
        """Async structured security audit."""
        chain = StructuredChain(self.client, STRUCTURED_SECURITY, SecurityAuditResult)
        return await chain.arun(code=code)

    async def astructured_performance(self, code: str, context: str = "") -> PerfReviewResult:
        """Async structured performance review."""
        chain = StructuredChain(self.client, STRUCTURED_PERFORMANCE, PerfReviewResult)
        return await chain.arun(code=code, context=context)

    def batch_review(self, code_files: dict[str, str]) -> dict[str, str]:
        """Review multiple files in parallel. Keys are paths, values are code."""
        from devai.core.batch import BatchRunner
        from devai.core.models import Message

        paths = list(code_files.keys())
        runner = BatchRunner(self.client)

        def to_messages(path: str) -> list[Message]:
            return [
                Message.system(CODE_REVIEW.system),
                Message.user(CODE_REVIEW.format(code=code_files[path])),
            ]

        results = runner.map(paths, to_messages)
        return dict(zip(paths, results))

    def review_project(self, directory: str, query: str | None = None) -> str:
        """Review a project directory with optional focus query."""
        from devai.project import CodeProject

        project = CodeProject(directory)
        context = project.build_context(query=query)
        return self._run_chain(CODE_REVIEW, code=context)

    def review_file(self, path: str) -> str:
        """Review a file by path."""
        content = Path(path).read_text(encoding="utf-8", errors="replace")
        return self.review(content)

    def review_directory(self, directory: str, pattern: str = "*.py") -> str:
        """Review all matching files in a directory."""
        root = Path(directory)
        if not root.exists():
            return f"Directory not found: {directory}"

        results: list[str] = []
        for path in sorted(root.rglob(pattern)):
            if any(part.startswith(".") for part in path.parts):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                review = self.review(content)
                results.append(f"## {path}\n\n{review}")
            except OSError:
                continue

        if not results:
            return f"No files matching '{pattern}' in {directory}"
        return "\n\n---\n\n".join(results)

    def full_review(self, code: str) -> dict[str, str]:
        """Run review, security, and complexity analysis."""
        return {
            "review": self.review(code),
            "security": self.security(code),
            "docstrings": self.docstring(code),
        }

    def stream_explain(self, code: str):
        """Stream an explanation of code."""
        messages = []
        if EXPLAIN.system:
            messages.append(Message.system(EXPLAIN.system))
        messages.append(Message.user(EXPLAIN.format(code=code)))
        return self.client.stream(messages)

    async def areview(self, code: str) -> str:
        """Async code review."""
        messages = [
            Message.system(CODE_REVIEW.system),
            Message.user(CODE_REVIEW.format(code=code)),
        ]
        return await self.client.acomplete(messages)
