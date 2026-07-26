"""Pre-built prompt templates for developer workflows."""

from devai.prompts.template import PromptTemplate

CODE_REVIEW = PromptTemplate(
    """You are an expert code reviewer. Review the following {language} code and provide:
1. A summary of what the code does
2. Issues found (bugs, security, performance, style)
3. Specific suggestions for improvement

```{language}
{code}
```

Be concise and actionable."""
)

DEBUG = PromptTemplate(
    """You are a debugging expert. Analyze this error and code to find the root cause.

Error:
```
{error}
```

Code:
```{language}
{code}
```

Provide:
1. Root cause analysis
2. Step-by-step fix
3. Prevention tips"""
)

COMMIT_MESSAGE = PromptTemplate(
    """Generate a conventional commit message for these changes.

Diff:
```
{diff}
```

Format: type(scope): description

Types: feat, fix, docs, style, refactor, test, chore
Keep the subject line under 72 characters."""
)

API_DESIGN = PromptTemplate(
    """Design a REST API for the following requirement:

{requirement}

Provide:
1. Endpoint list with methods and paths
2. Request/response schemas
3. Error handling strategy
4. Example curl commands"""
)

SECURITY_REVIEW = PromptTemplate(
    """Perform a security review of this code. Check for:
- Injection vulnerabilities (SQL, command, XSS)
- Authentication/authorization issues
- Sensitive data exposure
- Insecure dependencies or patterns

```{language}
{code}
```

Rate severity as CRITICAL/HIGH/MEDIUM/LOW for each finding."""
)

SQL_OPTIMIZE = PromptTemplate(
    """Optimize this SQL query for performance.

Database: {database}
Query:
```sql
{query}
```

Schema context:
{schema}

Provide the optimized query and explain changes."""
)

README_GEN = PromptTemplate(
    """Generate a README.md for this project.

Project name: {name}
Description: {description}
Language: {language}

Key files:
{files}

Include: installation, usage, configuration, and examples."""
)

TYPE_HINTS = PromptTemplate(
    """Add comprehensive Python type hints to this code.
Use modern syntax (list[str], str | None, etc.).

```python
{code}
```

Return only the typed code."""
)

REGEX_BUILD = PromptTemplate(
    """Build a regex pattern for this requirement:

{requirement}

Provide:
1. The regex pattern
2. Explanation of each part
3. Test cases (match and non-match examples)"""
)

LOG_ANALYSIS = PromptTemplate(
    """Analyze these application logs and identify issues.

Service: {service}
Time range: {time_range}

Logs:
```
{logs}
```

Provide: summary, errors found, patterns, and recommended actions."""
)

REFACTOR = PromptTemplate(
    """Refactor this {language} code to improve {goal}.

```{language}
{code}
```

Return the refactored code with a brief explanation of changes."""
)

EXPLAIN_CODE = PromptTemplate(
    """Explain this {language} code clearly for a developer.

```{language}
{code}
```

Cover: purpose, how it works, key patterns, and potential gotchas."""
)

UNIT_TEST = PromptTemplate(
    """Write unit tests for this {language} code using {framework}.

```{language}
{code}
```

Cover happy path, edge cases, and error conditions."""
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
    "explain_code": EXPLAIN_CODE,
    "unit_test": UNIT_TEST,
}
