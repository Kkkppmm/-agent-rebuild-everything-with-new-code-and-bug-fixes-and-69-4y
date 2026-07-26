"""Built-in prompt templates for common developer tasks."""

from devai.prompts.template import PromptTemplate

CODE_REVIEW = PromptTemplate(
    """You are an expert code reviewer. Review the following {language} code and provide:
1. A summary of what the code does
2. Issues found (bugs, security, performance)
3. Suggestions for improvement

Code:
```{language}
{code}
```

{extra_instructions}"""
)

DEBUG = PromptTemplate(
    """You are a debugging expert. Analyze this error and help fix it.

Error:
```
{error}
```

Code context:
```{language}
{code}
```

Stack trace:
```
{stack_trace}
```"""
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
    """Design a REST API for the following requirement.

Requirement:
{requirement}

Provide:
1. Endpoint list with methods
2. Request/response schemas
3. Error handling strategy
4. Authentication approach"""
)

SECURITY_REVIEW = PromptTemplate(
    """Perform a security review of this code. Check for:
- Injection vulnerabilities (SQL, XSS, command)
- Authentication/authorization flaws
- Sensitive data exposure
- Insecure dependencies
- Input validation issues

Code:
```{language}
{code}
```"""
)

SQL_OPTIMIZE = PromptTemplate(
    """Optimize this SQL query for performance.

Query:
```sql
{query}
```

Schema:
```
{schema}
```

Explain the optimization and provide the improved query."""
)

README_GEN = PromptTemplate(
    """Generate a README.md for this project.

Project name: {name}
Description: {description}
Language: {language}
Key features: {features}

Include: installation, usage, configuration, and license sections."""
)

TYPE_HINTS = PromptTemplate(
    """Add comprehensive Python type hints to this code.
Use modern syntax (list[str], X | None, etc.).

Code:
```python
{code}
```

Return only the typed code."""
)

REGEX_BUILD = PromptTemplate(
    """Build a regex pattern for this requirement.

Requirement: {requirement}
Test cases that should match: {should_match}
Test cases that should NOT match: {should_not_match}

Provide the regex, explanation, and Python usage example."""
)

LOG_ANALYSIS = PromptTemplate(
    """Analyze these application logs and identify:
1. Errors and their root causes
2. Performance issues
3. Anomalies or warnings
4. Recommended actions

Logs:
```
{logs}
```"""
)

EXPLAIN_CODE = PromptTemplate(
    """Explain this {language} code clearly for a developer.

Code:
```{language}
{code}
```

Cover: purpose, key logic, edge cases, and potential improvements."""
)

GENERATE_TESTS = PromptTemplate(
    """Generate unit tests for this {language} code using {framework}.

Code:
```{language}
{code}
```

Include edge cases and error handling tests."""
)

REFACTOR = PromptTemplate(
    """Refactor this {language} code for clarity and maintainability.

Code:
```{language}
{code}
```

Goals: {goals}

Return the refactored code with a brief explanation of changes."""
)
