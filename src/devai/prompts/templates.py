"""Prompt templates for DevAI."""

from __future__ import annotations

from dataclasses import dataclass, field
from string import Template
from typing import Any


@dataclass
class PromptTemplate:
    """A template for generating prompts with variable substitution."""

    template: str
    system: str = ""
    input_variables: list[str] = field(default_factory=list)

    def format(self, **kwargs: Any) -> str:
        missing = [v for v in self.input_variables if v not in kwargs]
        if missing:
            raise ValueError(f"Missing template variables: {missing}")
        return Template(self.template).safe_substitute(**kwargs)

    def to_messages(self, **kwargs: Any) -> list[dict[str, str]]:
        messages = []
        if self.system:
            messages.append({"role": "system", "content": self.system})
        messages.append({"role": "user", "content": self.format(**kwargs)})
        return messages


CODE_REVIEW = PromptTemplate(
    system="You are an expert code reviewer. Provide constructive, actionable feedback.",
    template=(
        "Review the following code and identify issues, improvements, "
        "and best practices:\n\n```\n$code\n```"
    ),
    input_variables=["code"],
)

DEBUG = PromptTemplate(
    system="You are an expert debugger. Analyze errors and provide fixes.",
    template=(
        "Debug the following code that produces this error:\n\n"
        "Error: $error\n\nCode:\n```\n$code\n```\n\n"
        "Explain the cause and provide a fixed version."
    ),
    input_variables=["code", "error"],
)

COMMIT_MESSAGE = PromptTemplate(
    system="You write clear, conventional commit messages.",
    template="Generate a commit message for this diff:\n\n```\n$diff\n```",
    input_variables=["diff"],
)

PR_DESCRIPTION = PromptTemplate(
    system="You write clear pull request descriptions.",
    template=(
        "Write a PR description for these changes:\n\n"
        "Title: $title\n\nDiff:\n```\n$diff\n```"
    ),
    input_variables=["title", "diff"],
)

CHANGELOG = PromptTemplate(
    system="You write clear changelogs following Keep a Changelog format.",
    template="Generate a changelog entry for version $version with these changes:\n\n$changes",
    input_variables=["version", "changes"],
)

CODE_TRANSLATE = PromptTemplate(
    system="You are an expert polyglot programmer.",
    template="Translate this $source_lang code to $target_lang:\n\n```\n$code\n```",
    input_variables=["code", "source_lang", "target_lang"],
)

ERROR_HANDLER = PromptTemplate(
    system="You add robust error handling to code.",
    template="Add comprehensive error handling to this code:\n\n```\n$code\n```",
    input_variables=["code"],
)

API_DESIGN = PromptTemplate(
    system="You are an API design expert.",
    template="Review and improve this API design:\n\n```\n$code\n```\n\nContext: $context",
    input_variables=["code", "context"],
)

SECURITY_REVIEW = PromptTemplate(
    system="You are a security expert. Identify vulnerabilities and suggest fixes.",
    template="Perform a security review of this code:\n\n```\n$code\n```",
    input_variables=["code"],
)

SQL_OPTIMIZE = PromptTemplate(
    system="You are a database performance expert.",
    template="Optimize this SQL query:\n\n```sql\n$query\n```\n\nContext: $context",
    input_variables=["query", "context"],
)

README_GEN = PromptTemplate(
    system="You write clear, comprehensive README files.",
    template="Generate a README for this project:\n\nProject: $project\n\n$description",
    input_variables=["project", "description"],
)

TYPE_HINTS = PromptTemplate(
    system="You add precise Python type hints.",
    template="Add type hints to this Python code:\n\n```python\n$code\n```",
    input_variables=["code"],
)

REGEX_BUILD = PromptTemplate(
    system="You build and explain regular expressions.",
    template="Build a regex for: $description\n\nTest cases: $test_cases",
    input_variables=["description", "test_cases"],
)

LOG_ANALYSIS = PromptTemplate(
    system="You analyze log files and identify issues.",
    template="Analyze these logs and identify errors, warnings, and patterns:\n\n```\n$logs\n```",
    input_variables=["logs"],
)

REFACTOR = PromptTemplate(
    system="You refactor code for clarity, maintainability, and performance.",
    template="Refactor this code:\n\n```\n$code\n```\n\nGoals: $goals",
    input_variables=["code", "goals"],
)

DOCSTRING_GEN = PromptTemplate(
    system="You write clear, Google-style docstrings.",
    template="Generate docstrings for this code:\n\n```\n$code\n```",
    input_variables=["code"],
)

EXPLAIN = PromptTemplate(
    system="You explain code clearly for developers of all levels.",
    template="Explain this code:\n\n```\n$code\n```",
    input_variables=["code"],
)

TEST_GEN = PromptTemplate(
    system="You write comprehensive unit tests.",
    template="Generate unit tests for this code using $framework:\n\n```\n$code\n```",
    input_variables=["code", "framework"],
)

DIFF_REVIEW = PromptTemplate(
    system=(
        "You are an expert code reviewer focused on pull request diffs. "
        "Highlight regressions, missing tests, and risky changes."
    ),
    template=(
        "Review this git diff and provide actionable feedback on the changes:\n\n"
        "```diff\n$diff\n```\n\n"
        "Focus on: correctness, edge cases, test coverage, and breaking changes."
    ),
    input_variables=["diff"],
)

PERFORMANCE_REVIEW = PromptTemplate(
    system="You are a performance engineering expert.",
    template=(
        "Analyze this code for performance issues and suggest optimizations:\n\n"
        "```\n$code\n```\n\n"
        "Context: $context"
    ),
    input_variables=["code", "context"],
)

DOCKERFILE_REVIEW = PromptTemplate(
    system="You are a container and DevOps expert.",
    template=(
        "Review this Dockerfile for security, size, and best practices:\n\n"
        "```dockerfile\n$dockerfile\n```"
    ),
    input_variables=["dockerfile"],
)

MIGRATION_PLAN = PromptTemplate(
    system="You plan safe, incremental software migrations.",
    template=(
        "Create a migration plan from $source to $target:\n\n"
        "Current code or setup:\n```\n$code\n```\n\n"
        "Constraints: $constraints"
    ),
    input_variables=["source", "target", "code", "constraints"],
)

CODE_GEN = PromptTemplate(
    system="You write clean, production-ready code with tests and error handling.",
    template=(
        "Generate $language code for this specification:\n\n$spec\n\n"
        "Include docstrings, type hints where appropriate, and handle edge cases."
    ),
    input_variables=["spec", "language"],
)

FIX_LINT = PromptTemplate(
    system="You fix linter and static analysis issues while preserving behavior.",
    template=(
        "Fix the linter issues in this code:\n\nLinter output:\n```\n$lint_output\n```\n\n"
        "Code:\n```\n$code\n```"
    ),
    input_variables=["code", "lint_output"],
)

DEP_AUDIT = PromptTemplate(
    system="You audit dependencies for security risks, outdated packages, and licensing issues.",
    template=(
        "Audit these project dependencies for security vulnerabilities, outdated versions, "
        "and licensing concerns:\n\n```\n$dependencies\n```\n\nProject context: $context"
    ),
    input_variables=["dependencies", "context"],
)

ARCHITECTURE = PromptTemplate(
    system="You describe software architecture clearly, including Mermaid diagrams when helpful.",
    template=(
        "Describe the architecture of this codebase. Include a Mermaid diagram if appropriate:\n\n"
        "```\n$code\n```\n\nContext: $context"
    ),
    input_variables=["code", "context"],
)

STRUCTURED_REVIEW = PromptTemplate(
    system=(
        "You are an expert code reviewer. Respond with valid JSON matching this schema: "
        '{"summary": "string", "score": 1-10, "issues": [{"severity": "low|medium|high|critical", '
        '"line": null or int, "message": "string", "suggestion": "string or null"}]}'
    ),
    template="Review this code and return structured JSON:\n\n```\n$code\n```",
    input_variables=["code"],
)

STRUCTURED_SECURITY = PromptTemplate(
    system=(
        "You are a security expert. Respond with valid JSON matching this schema: "
        '{"summary": "string", "risk_level": "low|medium|high|critical", '
        '"findings": [{"severity": "string", "category": "string", '
        '"description": "string", "remediation": "string or null"}]}'
    ),
    template="Perform a security audit and return structured JSON:\n\n```\n$code\n```",
    input_variables=["code"],
)

STRUCTURED_PERFORMANCE = PromptTemplate(
    system=(
        "You are a performance expert. Respond with valid JSON matching this schema: "
        '{"summary": "string", "issues": [{"area": "string", "impact": "low|medium|high", '
        '"description": "string", "fix": "string or null"}]}'
    ),
    template="Analyze performance and return structured JSON:\n\n```\n$code\n```\n\nContext: $context",
    input_variables=["code", "context"],
)

INCIDENT_TRIAGE = PromptTemplate(
    system=(
        "You triage production incidents for developers. Be concise and actionable."
    ),
    template=(
        "Triage this incident:\n\nSymptoms:\n$symptoms\n\n"
        "Logs:\n```\n$logs\n```\n\n"
        "Provide: likely cause, immediate steps, and follow-up investigation."
    ),
    input_variables=["symptoms", "logs"],
)

DEP_UPGRADE = PromptTemplate(
    system="You recommend safe dependency upgrades for Python projects.",
    template=(
        "Suggest dependency upgrades for:\n\n```\n$dependencies\n```\n\n"
        "Constraints: $constraints\n\n"
        "Include version targets, breaking-change risks, and migration notes."
    ),
    input_variables=["dependencies", "constraints"],
)

SUMMARIZE_CHANGES = PromptTemplate(
    system="You summarize code changes clearly for developers and reviewers.",
    template=(
        "Summarize these changes for a pull request or release notes:\n\n"
        "```\n$diff\n```\n\n"
        "Audience: $audience"
    ),
    input_variables=["diff", "audience"],
)

OPENAPI_REVIEW = PromptTemplate(
    system=(
        "You are an API design and OpenAPI expert. Review specs for consistency, "
        "security, versioning, and developer experience."
    ),
    template=(
        "Review this OpenAPI specification for design issues, missing error responses, "
        "security gaps, and improvements:\n\n```yaml\n$spec\n```\n\n"
        "Context: $context"
    ),
    input_variables=["spec", "context"],
)

TEST_FAILURE = PromptTemplate(
    system=(
        "You are an expert Python test debugger. Analyze pytest/unittest failures "
        "and provide root cause analysis with concrete fixes."
    ),
    template=(
        "Analyze these test failures and explain root causes with fixes:\n\n"
        "```\n$output\n```\n\n"
        "Source code context (if available):\n```\n$code\n```"
    ),
    input_variables=["output", "code"],
)

STACK_TRACE = PromptTemplate(
    system=(
        "You are an expert debugger. Analyze stack traces and explain the failure "
        "with actionable fixes."
    ),
    template=(
        "Analyze this stack trace and explain the failure:\n\n```\n$trace\n```\n\n"
        "Additional context:\n$context"
    ),
    input_variables=["trace", "context"],
)

CONFIG_REVIEW = PromptTemplate(
    system=(
        "You review project configuration files (pyproject.toml, YAML, JSON, TOML) "
        "for correctness, security, and best practices."
    ),
    template=(
        "Review this $config_type configuration file:\n\n```\n$config\n```\n\n"
        "Context: $context"
    ),
    input_variables=["config", "config_type", "context"],
)

NOTEBOOK_REVIEW = PromptTemplate(
    system=(
        "You review Jupyter notebooks for code quality, reproducibility, "
        "and data-science best practices."
    ),
    template=(
        "Review this Jupyter notebook content:\n\n$notebook\n\n"
        "Focus on: code quality, missing tests, hardcoded values, "
        "reproducibility, and documentation."
    ),
    input_variables=["notebook"],
)

METRICS_REVIEW = PromptTemplate(
    system=(
        "You analyze static code metrics and recommend maintainability improvements. "
        "Focus on complexity hotspots, oversized files, and structural issues."
    ),
    template=(
        "Review these static code metrics and recommend improvements:\n\n$metrics\n\n"
        "Prioritize high-complexity functions and oversized files."
    ),
    input_variables=["metrics"],
)

COVERAGE_REVIEW = PromptTemplate(
    system=(
        "You analyze test coverage reports and recommend where to add tests. "
        "Focus on uncovered critical paths, edge cases, and high-risk gaps."
    ),
    template=(
        "Review this test coverage report and recommend where to add tests:\n\n$coverage\n\n"
        "Prioritize files with low coverage and critical business logic."
    ),
    input_variables=["coverage"],
)
