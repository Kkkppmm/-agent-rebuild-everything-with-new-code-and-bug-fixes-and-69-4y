"""Built-in prompt templates for common developer tasks."""

from devai.prompts.template import PromptTemplate

CODE_REVIEW = PromptTemplate(
    template=(
        "You are an expert code reviewer. Review the following {language} code.\n\n"
        "Focus on: bugs, security issues, performance, readability, and best practices.\n"
        "Provide actionable feedback with severity labels (critical, warning, suggestion).\n\n"
        "```\n{code}\n```"
    ),
    input_variables=["language", "code"],
)

DEBUG_ERROR = PromptTemplate(
    template=(
        "You are a debugging assistant. Help diagnose and fix this error.\n\n"
        "Error message:\n{error}\n\n"
        "Relevant code:\n```\n{code}\n```\n\n"
        "Explain the root cause and provide a fix."
    ),
    input_variables=["error", "code"],
)

EXPLAIN_CODE = PromptTemplate(
    template=(
        "Explain the following {language} code clearly for a developer.\n"
        "Cover: purpose, key logic, data flow, and any non-obvious behavior.\n\n"
        "```\n{code}\n```"
    ),
    input_variables=["language", "code"],
)

GENERATE_TESTS = PromptTemplate(
    template=(
        "Generate comprehensive unit tests for this {language} code using {framework}.\n"
        "Include edge cases and clear test names.\n\n"
        "```\n{code}\n```"
    ),
    input_variables=["language", "framework", "code"],
)

REFACTOR = PromptTemplate(
    template=(
        "Refactor the following {language} code.\n"
        "Goals: {goals}\n"
        "Preserve behavior. Show the refactored code with a brief explanation.\n\n"
        "```\n{code}\n```"
    ),
    input_variables=["language", "goals", "code"],
)

WRITE_DOCS = PromptTemplate(
    template=(
        "Write clear documentation for this {language} code.\n"
        "Format: {format}\n"
        "Include parameters, return values, examples, and edge cases.\n\n"
        "```\n{code}\n```"
    ),
    input_variables=["language", "format", "code"],
)

COMMIT_MESSAGE = PromptTemplate(
    template=(
        "Generate a concise git commit message for the following diff.\n"
        "Use conventional commit format (feat, fix, refactor, docs, test, chore).\n"
        "Include a subject line (max 72 chars) and optional body.\n\n"
        "```diff\n{diff}\n```"
    ),
    input_variables=["diff"],
)

API_DESIGN = PromptTemplate(
    template=(
        "Design a REST API for: {description}\n"
        "Language/framework: {language}\n"
        "Include endpoints, request/response schemas, error codes, and auth strategy."
    ),
    input_variables=["description", "language"],
)
