"""Pre-built developer prompt templates."""

from devai.prompts.template import PromptTemplate

CODE_REVIEW = PromptTemplate(
    "You are an expert code reviewer. Review the following {language} code and provide "
    "actionable feedback on bugs, performance, readability, and best practices.\n\n"
    "```{language}\n{code}\n```\n\n"
    "Provide your review in sections: Summary, Issues, Suggestions.",
    input_variables=["language", "code"],
)

DEBUG = PromptTemplate(
    "You are a debugging expert. Analyze this error and code to find the root cause "
    "and suggest a fix.\n\n"
    "Error:\n{error}\n\n"
    "Code:\n```{language}\n{code}\n```\n\n"
    "Explain the root cause and provide a fixed code snippet.",
    input_variables=["error", "language", "code"],
)

COMMIT_MESSAGE = PromptTemplate(
    "Generate a concise, conventional commit message for the following git diff.\n\n"
    "{diff}\n\n"
    "Format: <type>(<scope>): <description>\n"
    "Types: feat, fix, docs, style, refactor, test, chore",
    input_variables=["diff"],
)

API_DESIGN = PromptTemplate(
    "You are an API design expert. Review and improve this API design.\n\n"
    "Language: {language}\n"
    "Description: {description}\n\n"
    "```{language}\n{code}\n```\n\n"
    "Suggest improvements for naming, error handling, versioning, and documentation.",
    input_variables=["language", "description", "code"],
)

SECURITY_REVIEW = PromptTemplate(
    "You are a security engineer. Perform a security review of this code.\n\n"
    "```{language}\n{code}\n```\n\n"
    "Check for: injection, XSS, auth issues, data exposure, insecure defaults. "
    "Rate severity as Critical/High/Medium/Low.",
    input_variables=["language", "code"],
)

SQL_OPTIMIZE = PromptTemplate(
    "You are a database performance expert. Optimize this SQL query.\n\n"
    "Database: {database}\n"
    "Schema:\n{schema}\n\n"
    "Query:\n```sql\n{query}\n```\n\n"
    "Suggest an optimized query and explain index recommendations.",
    input_variables=["database", "schema", "query"],
)

README_GEN = PromptTemplate(
    "Generate a professional README.md for this project.\n\n"
    "Project name: {name}\n"
    "Description: {description}\n"
    "Language: {language}\n\n"
    "Code overview:\n```{language}\n{code}\n```\n\n"
    "Include: title, description, installation, usage, and license sections.",
    input_variables=["name", "description", "language", "code"],
)

TYPE_HINTS = PromptTemplate(
    "Add comprehensive Python type hints to this code. Return only the typed code.\n\n"
    "```python\n{code}\n```",
    input_variables=["code"],
)

REGEX_BUILD = PromptTemplate(
    "Build a regex pattern for this requirement. Explain each part.\n\n"
    "Requirement: {requirement}\n"
    "Test cases that should match: {match_cases}\n"
    "Test cases that should NOT match: {no_match_cases}",
    input_variables=["requirement", "match_cases", "no_match_cases"],
)

LOG_ANALYSIS = PromptTemplate(
    "Analyze these application logs and identify issues, patterns, and root causes.\n\n"
    "Service: {service}\n"
    "Time range: {time_range}\n\n"
    "Logs:\n```\n{logs}\n```\n\n"
    "Provide: summary, errors found, patterns, and recommended actions.",
    input_variables=["service", "time_range", "logs"],
)

EXPLAIN_CODE = PromptTemplate(
    "Explain this {language} code clearly for a developer.\n\n"
    "```{language}\n{code}\n```\n\n"
    "Cover: purpose, key logic, and any non-obvious behavior.",
    input_variables=["language", "code"],
)

TEST_GENERATION = PromptTemplate(
    "Generate comprehensive unit tests for this {language} code using {framework}.\n\n"
    "```{language}\n{code}\n```\n\n"
    "Cover edge cases, error paths, and happy paths.",
    input_variables=["language", "framework", "code"],
)
