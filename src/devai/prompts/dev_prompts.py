"""Pre-built prompt templates for common developer tasks."""

from devai.prompts.template import PromptTemplate

CODE_REVIEW = PromptTemplate(
    name="code_review",
    template="""You are an expert code reviewer. Review the following {language} code for:
- Bugs and logic errors
- Performance issues
- Security vulnerabilities
- Style and readability
- Best practices

Provide specific, actionable feedback with line references where possible.

Code:
```{language}
{code}
```

Context: {context}""",
)

DEBUG = PromptTemplate(
    name="debug",
    template="""You are a debugging expert. Analyze this error and help fix it.

Error:
{error}

Code:
```{language}
{code}
```

Stack trace (if any):
{stack_trace}

Provide:
1. Root cause analysis
2. Step-by-step fix
3. Prevention tips""",
)

COMMIT_MESSAGE = PromptTemplate(
    name="commit_message",
    template="""Generate a clear, conventional commit message for this diff.

Diff:
{diff}

Format: <type>(<scope>): <description>
Types: feat, fix, docs, style, refactor, test, chore
Keep the subject under 72 characters. Add a body if needed.""",
)

API_DESIGN = PromptTemplate(
    name="api_design",
    template="""Design a REST API for: {description}

Requirements:
{requirements}

Provide:
1. Endpoint list with methods and paths
2. Request/response schemas
3. Authentication approach
4. Error handling strategy
5. Example requests""",
)

SECURITY_REVIEW = PromptTemplate(
    name="security_review",
    template="""Perform a security review of this code. Check for:
- Injection vulnerabilities (SQL, XSS, command)
- Authentication/authorization flaws
- Sensitive data exposure
- Insecure dependencies
- OWASP Top 10 issues

Code:
```{language}
{code}
```

Rate severity (Critical/High/Medium/Low) for each finding.""",
)

SQL_OPTIMIZE = PromptTemplate(
    name="sql_optimize",
    template="""Optimize this SQL query for performance.

Query:
{query}

Schema/context:
{schema}

Provide:
1. Optimized query
2. Index recommendations
3. Explanation of improvements""",
)

README_GEN = PromptTemplate(
    name="readme_gen",
    template="""Generate a professional README.md for this project.

Project name: {project_name}
Description: {description}
Tech stack: {tech_stack}
Key features: {features}

Include: installation, usage, configuration, and contributing sections.""",
)

TYPE_HINTS = PromptTemplate(
    name="type_hints",
    template="""Add complete Python type hints to this code. Use modern syntax (Python 3.10+).

Code:
```python
{code}
```

Return only the typed code with no explanation.""",
)

REGEX_BUILD = PromptTemplate(
    name="regex_build",
    template="""Build a regex pattern for: {description}

Test cases that should match: {should_match}
Test cases that should NOT match: {should_not_match}

Provide the regex, explanation, and Python usage example.""",
)

LOG_ANALYSIS = PromptTemplate(
    name="log_analysis",
    template="""Analyze these application logs and identify issues.

Logs:
{logs}

Time range: {time_range}

Provide:
1. Summary of events
2. Errors and warnings
3. Performance issues
4. Recommended actions""",
)

REFACTOR = PromptTemplate(
    name="refactor",
    template="""Refactor this {language} code for: {goal}

Current code:
```{language}
{code}
```

Constraints: {constraints}

Return the refactored code with a brief explanation of changes.""",
)

EXPLAIN_CODE = PromptTemplate(
    name="explain_code",
    template="""Explain this {language} code clearly for a developer.

Code:
```{language}
{code}
```

Audience level: {audience}
Include: purpose, how it works, and any notable patterns.""",
)

GENERATE_TESTS = PromptTemplate(
    name="generate_tests",
    template="""Generate {framework} tests for this code.

Code:
```{language}
{code}
```

Cover: happy path, edge cases, and error conditions.
Use descriptive test names.""",
)
