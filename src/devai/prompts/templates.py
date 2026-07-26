"""Prompt templates for developer workflows."""

from __future__ import annotations

from dataclasses import dataclass
from string import Template
from typing import Any


@dataclass
class PromptTemplate:
    """A reusable prompt template with variable substitution."""

    name: str
    template: str
    system: str = "You are an expert software engineer."

    def render(self, **kwargs: Any) -> str:
        return Template(self.template).safe_substitute(**kwargs)

    def to_messages(self, **kwargs: Any) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": self.system},
            {"role": "user", "content": self.render(**kwargs)},
        ]


CODE_REVIEW = PromptTemplate(
    name="code_review",
    template=(
        "Review the following code for bugs, performance issues, and style problems.\n"
        "Provide actionable feedback with severity levels.\n\n"
        "Language: $language\n"
        "```\n$code\n```"
    ),
)

DEBUG = PromptTemplate(
    name="debug",
    template=(
        "Help debug the following error.\n\n"
        "Error:\n$error\n\n"
        "Code:\n```\n$code\n```\n\n"
        "Context: $context"
    ),
)

COMMIT_MESSAGE = PromptTemplate(
    name="commit_message",
    template=(
        "Generate a concise, conventional commit message for this diff.\n\n"
        "```diff\n$diff\n```"
    ),
    system="You write clear, conventional commit messages.",
)

API_DESIGN = PromptTemplate(
    name="api_design",
    template=(
        "Design a REST API for the following requirements:\n\n"
        "$requirements\n\n"
        "Include endpoints, request/response schemas, and error handling."
    ),
)

SECURITY_REVIEW = PromptTemplate(
    name="security_review",
    template=(
        "Perform a security review of this code. Check for OWASP Top 10 "
        "vulnerabilities, injection risks, and insecure defaults.\n\n"
        "```\n$code\n```"
    ),
    system="You are a security engineer specializing in application security.",
)

SQL_OPTIMIZE = PromptTemplate(
    name="sql_optimize",
    template=(
        "Optimize the following SQL query. Explain the changes and expected "
        "performance improvement.\n\n"
        "Schema:\n$schema\n\n"
        "Query:\n```sql\n$query\n```"
    ),
)

README_GEN = PromptTemplate(
    name="readme_gen",
    template=(
        "Generate a README.md for this project.\n\n"
        "Project name: $name\n"
        "Description: $description\n"
        "Tech stack: $tech_stack\n"
        "Key features: $features"
    ),
)

TYPE_HINTS = PromptTemplate(
    name="type_hints",
    template=(
        "Add complete Python type hints to the following code. "
        "Use modern syntax (list[str], X | None, etc.).\n\n"
        "```python\n$code\n```"
    ),
)

REGEX_BUILD = PromptTemplate(
    name="regex_build",
    template=(
        "Build a regex pattern for: $description\n\n"
        "Provide the pattern, explanation, and test cases."
    ),
)

LOG_ANALYSIS = PromptTemplate(
    name="log_analysis",
    template=(
        "Analyze these application logs and identify issues, patterns, "
        "and recommended actions.\n\n"
        "```\n$logs\n```"
    ),
)

REFACTOR = PromptTemplate(
    name="refactor",
    template=(
        "Refactor the following code to improve $goal.\n\n"
        "```\n$code\n```\n\n"
        "Explain each change and preserve existing behavior."
    ),
)

TEST_GEN = PromptTemplate(
    name="test_gen",
    template=(
        "Generate unit tests for the following code using $framework.\n\n"
        "```\n$code\n```"
    ),
)

EXPLAIN_CODE = PromptTemplate(
    name="explain_code",
    template=(
        "Explain the following code in clear, concise language suitable for "
        "a developer.\n\n"
        "Language: $language\n"
        "```\n$code\n```"
    ),
)

ALL_TEMPLATES: dict[str, PromptTemplate] = {
    t.name: t
    for t in [
        CODE_REVIEW,
        DEBUG,
        COMMIT_MESSAGE,
        API_DESIGN,
        SECURITY_REVIEW,
        SQL_OPTIMIZE,
        README_GEN,
        TYPE_HINTS,
        REGEX_BUILD,
        LOG_ANALYSIS,
        REFACTOR,
        TEST_GEN,
        EXPLAIN_CODE,
    ]
}


def get_template(name: str) -> PromptTemplate:
    """Look up a prompt template by name."""
    if name not in ALL_TEMPLATES:
        available = ", ".join(sorted(ALL_TEMPLATES))
        raise KeyError(f"Unknown template '{name}'. Available: {available}")
    return ALL_TEMPLATES[name]
