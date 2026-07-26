"""Developer-focused prompt templates."""

from devai.prompts.template import PromptTemplate

CODE_REVIEW = PromptTemplate(
    """You are an expert code reviewer. Review the following {language} code and provide:
1. A summary of what the code does
2. Potential bugs or issues
3. Performance concerns
4. Suggestions for improvement

```{language}
{code}
```"""
)

DEBUG = PromptTemplate(
    """You are a debugging expert. Analyze this error and code to find the root cause and fix.

Error:
{error}

Code:
```{language}
{code}
```

Provide: root cause, explanation, and a fixed code snippet."""
)

COMMIT_MESSAGE = PromptTemplate(
    """Generate a concise, conventional commit message for these changes.

Diff:
```
{diff}
```

Format: <type>(<scope>): <description>

Types: feat, fix, docs, style, refactor, test, chore"""
)

API_DESIGN = PromptTemplate(
    """Design a REST API for the following requirement:

{requirement}

Provide: endpoints, request/response schemas, status codes, and example curl commands."""
)

SECURITY_REVIEW = PromptTemplate(
    """Perform a security review of this code. Identify vulnerabilities (OWASP Top 10),
insecure patterns, and provide remediation steps.

```{language}
{code}
```"""
)

SQL_OPTIMIZE = PromptTemplate(
    """Optimize this SQL query for performance. Explain the issues and provide an improved version.

Database: {database}
Query:
```sql
{query}
```"""
)

README_GEN = PromptTemplate(
    """Generate a professional README.md for this project.

Project name: {name}
Description: {description}
Language: {language}
Key features: {features}

Include: badges, installation, usage, API reference, and license sections."""
)

TYPE_HINTS = PromptTemplate(
    """Add complete Python type hints to this code. Preserve behavior exactly.

```python
{code}
```

Return only the typed code."""
)

REGEX_BUILD = PromptTemplate(
    """Build a regex pattern for this requirement:

{requirement}

Provide: the pattern, explanation, and test examples that match and don't match."""
)

LOG_ANALYSIS = PromptTemplate(
    """Analyze these application logs and identify issues, patterns, and recommended actions.

```
{logs}
```"""
)

REFACTOR = PromptTemplate(
    """Refactor this {language} code to improve readability, maintainability, and follow best practices.
Preserve all existing behavior.

```{language}
{code}
```

Return the refactored code with a brief summary of changes."""
)

TEST_GEN = PromptTemplate(
    """Generate comprehensive unit tests for this {language} code using {framework}.

```{language}
{code}
```

Cover edge cases, error paths, and happy paths."""
)

DOCSTRING_GEN = PromptTemplate(
    """Add Google-style docstrings to all functions and classes in this Python code.

```python
{code}
```

Return the complete code with docstrings."""
)

ALL_PROMPTS = {
    "code_review": CODE_REVIEW,
    "debug": DEBUG,
    "commit_message": COMMIT_MESSAGE,
    "api_design": API_DESIGN,
    "security_review": SECURITY_REVIEW,
    "sql_optimize": SQL_OPTIMIZE,
    "readme_gen": README_GEN,
    "type_hints": TYPE_HINTS,
    "regex_build": REGEX_BUILD,
    "log_analysis": LOG_ANALYSIS,
    "refactor": REFACTOR,
    "test_gen": TEST_GEN,
    "docstring_gen": DOCSTRING_GEN,
}
