"""Developer-focused prompt templates."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PromptTemplate:
    """Simple string template with named placeholders."""

    template: str

    def format(self, **kwargs: str) -> str:
        return self.template.format(**kwargs)

    def __call__(self, **kwargs: str) -> str:
        return self.format(**kwargs)


CODE_REVIEW = PromptTemplate(
    """Review the following code for bugs, style issues, and improvements.
Provide actionable feedback with severity levels (critical, warning, info).

```{language}
{code}
```"""
)

DEBUG = PromptTemplate(
    """Debug the following error. Explain the root cause and provide a fix.

Error:
{error}

Code:
```{language}
{code}
```"""
)

COMMIT_MESSAGE = PromptTemplate(
    """Generate a concise, conventional commit message for the following diff.
Use imperative mood. Include a subject line (max 72 chars) and optional body.

```
{diff}
```"""
)

API_DESIGN = PromptTemplate(
    """Design a REST API for the following requirements.
Include endpoints, request/response schemas, and error handling.

Requirements:
{requirements}"""
)

SECURITY_REVIEW = PromptTemplate(
    """Perform a security review of the following code.
Check for injection, auth issues, secrets exposure, and OWASP Top 10 risks.

```{language}
{code}
```"""
)

SQL_OPTIMIZE = PromptTemplate(
    """Optimize the following SQL query for performance.
Explain the changes and expected impact.

```sql
{query}
```

Schema context:
{schema}"""
)

README_GEN = PromptTemplate(
    """Generate a README.md for the following project.
Include installation, usage, configuration, and development sections.

Project name: {name}
Description: {description}
Key files:
{files}"""
)

TYPE_HINTS = PromptTemplate(
    """Add complete Python type hints to the following code.
Preserve behavior; only add annotations and necessary imports.

```python
{code}
```"""
)

REGEX_BUILD = PromptTemplate(
    """Build a regex pattern for the following requirement.
Provide the pattern, explanation, and test cases.

Requirement: {requirement}
Test strings: {test_strings}"""
)

LOG_ANALYSIS = PromptTemplate(
    """Analyze the following application logs.
Identify errors, warnings, patterns, and recommended actions.

```
{logs}
```"""
)

REFACTOR = PromptTemplate(
    """Refactor the following code for clarity and maintainability.
Explain each change and preserve existing behavior.

```{language}
{code}
```

Goals: {goals}"""
)

EXPLAIN_CODE = PromptTemplate(
    """Explain the following code clearly for a developer.
Cover purpose, key logic, edge cases, and complexity.

```{language}
{code}
```"""
)

GENERATE_TESTS = PromptTemplate(
    """Generate unit tests for the following code using {framework}.
Cover happy path, edge cases, and error conditions.

```{language}
{code}
```"""
)

DOCSTRING_GEN = PromptTemplate(
    """Add comprehensive docstrings to the following Python code.
Use Google style docstrings.

```python
{code}
```"""
)
