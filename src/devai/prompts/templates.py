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
