"""Pre-built developer prompt templates."""

from devai.prompts.template import PromptTemplate

CODE_REVIEW = PromptTemplate(
    template="""You are an expert code reviewer. Review the following {language} code and provide:
1. A summary of what the code does
2. Potential bugs or issues
3. Performance concerns
4. Suggestions for improvement

```{language}
{code}
```""",
    input_variables=["language", "code"],
)

DEBUG = PromptTemplate(
    template="""You are a debugging expert. Analyze this error and code to find the root cause and suggest a fix.

Error:
{error}

Code:
```
{code}
```

Provide:
1. Root cause analysis
2. Step-by-step fix
3. Prevention tips""",
    input_variables=["error", "code"],
)

COMMIT_MESSAGE = PromptTemplate(
    template="""Generate a concise, conventional commit message for these changes.

Diff:
```
{diff}
```

Format: type(scope): description

Types: feat, fix, docs, style, refactor, test, chore""",
    input_variables=["diff"],
)

API_DESIGN = PromptTemplate(
    template="""Design a REST API for the following requirements:

{requirements}

Provide:
1. Endpoint list with methods and paths
2. Request/response schemas
3. Error handling strategy
4. Authentication approach""",
    input_variables=["requirements"],
)

SECURITY_REVIEW = PromptTemplate(
    template="""Perform a security review of this code. Identify vulnerabilities and suggest fixes.

```{language}
{code}
```

Check for: injection, XSS, auth issues, data exposure, insecure dependencies.""",
    input_variables=["language", "code"],
)

SQL_OPTIMIZE = PromptTemplate(
    template="""Optimize this SQL query for performance.

Database: {database}

```sql
{query}
```

Provide the optimized query and explain the improvements.""",
    input_variables=["database", "query"],
)

README_GEN = PromptTemplate(
    template="""Generate a professional README.md for this project.

Project name: {name}
Description: {description}
Tech stack: {tech_stack}
Key features: {features}

Include: installation, usage, configuration, and contributing sections.""",
    input_variables=["name", "description", "tech_stack", "features"],
)

TYPE_HINTS = PromptTemplate(
    template="""Add comprehensive Python type hints to this code. Return only the typed code.

```python
{code}
```""",
    input_variables=["code"],
)

REGEX_BUILD = PromptTemplate(
    template="""Build a regex pattern for this requirement:

{description}

Provide:
1. The regex pattern
2. Explanation of each part
3. Test cases (match and non-match examples)""",
    input_variables=["description"],
)

LOG_ANALYSIS = PromptTemplate(
    template="""Analyze these application logs and identify issues.

```
{logs}
```

Provide:
1. Summary of events
2. Errors and warnings found
3. Root cause hypotheses
4. Recommended actions""",
    input_variables=["logs"],
)

REFACTOR = PromptTemplate(
    template="""Refactor this {language} code for better readability, maintainability, and performance.

```{language}
{code}
```

Goals: {goals}

Return the refactored code with a brief explanation of changes.""",
    input_variables=["language", "code", "goals"],
)

TEST_GEN = PromptTemplate(
    template="""Generate comprehensive unit tests for this {language} code using {framework}.

```{language}
{code}
```

Include edge cases and error handling tests.""",
    input_variables=["language", "code", "framework"],
)

EXPLAIN_CODE = PromptTemplate(
    template="""Explain this {language} code in clear, simple terms for a developer.

```{language}
{code}
```

Cover: purpose, how it works, key patterns, and potential gotchas.""",
    input_variables=["language", "code"],
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
    "explain_code": EXPLAIN_CODE,
}
