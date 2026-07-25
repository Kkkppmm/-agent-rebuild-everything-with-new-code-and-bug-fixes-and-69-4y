"""Pre-built prompt templates for common developer tasks."""

from devai.prompts.template import PromptTemplate

CODE_REVIEW = PromptTemplate(
    "Review the following {language} code and provide actionable feedback.\n\n"
    "Focus on bugs, security issues, performance, and readability.\n\n"
    "```\n{code}\n```",
    system=(
        "You are a senior software engineer performing code review. "
        "Be concise, specific, and prioritize critical issues."
    ),
)

EXPLAIN_CODE = PromptTemplate(
    "Explain what this {language} code does in plain language.\n\n"
    "```\n{code}\n```",
    system="You are a patient programming tutor explaining code to developers.",
)

GENERATE_TESTS = PromptTemplate(
    "Write unit tests for the following {language} code using {framework}.\n\n"
    "```\n{code}\n```\n\n"
    "Cover edge cases and include clear test names.",
    system="You are an expert test engineer. Output only test code unless asked otherwise.",
)

REFACTOR = PromptTemplate(
    "Refactor this {language} code to improve {goal}.\n\n"
    "```\n{code}\n```\n\n"
    "Return the improved code with a brief summary of changes.",
    system="You are a refactoring specialist. Preserve behavior unless told otherwise.",
)

DEBUG = PromptTemplate(
    "Help debug this error in {language}:\n\n"
    "Error:\n{error}\n\n"
    "Code:\n```\n{code}\n```\n\n"
    "Explain the root cause and suggest a fix.",
    system="You are a debugging expert. Identify root causes, not just symptoms.",
)

DOCSTRING = PromptTemplate(
    "Add clear docstrings and inline comments to this {language} code:\n\n"
    "```\n{code}\n```",
    system="You are a documentation specialist. Follow language conventions.",
)

COMMIT_MESSAGE = PromptTemplate(
    "Write a conventional commit message for these changes:\n\n{diff}",
    system=(
        "You write concise, conventional commit messages. "
        "Use imperative mood and explain the why when non-obvious."
    ),
)

__all__ = [
    "CODE_REVIEW",
    "COMMIT_MESSAGE",
    "DEBUG",
    "DOCSTRING",
    "EXPLAIN_CODE",
    "GENERATE_TESTS",
    "REFACTOR",
]
