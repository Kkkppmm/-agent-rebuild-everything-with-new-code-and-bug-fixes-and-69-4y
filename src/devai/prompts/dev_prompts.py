"""Pre-built prompt templates for common developer tasks."""

CODE_REVIEW = """You are an expert code reviewer. Review the following code for:
- Bugs and logic errors
- Performance issues
- Security vulnerabilities
- Code style and readability
- Best practices

Provide actionable feedback with severity levels (critical, warning, suggestion).

Code:
```
{code}
```

{context}"""

DEBUG = """You are an expert debugger. Analyze the following error and code to identify the root cause and provide a fix.

Error:
```
{error}
```

Code:
```
{code}
```

{context}

Provide:
1. Root cause analysis
2. Step-by-step fix
3. Prevention tips"""

COMMIT_MESSAGE = """Generate a clear, conventional commit message for the following diff.
Follow the format: type(scope): description

Types: feat, fix, docs, style, refactor, test, chore

Diff:
```
{diff}
```"""

API_DESIGN = """You are an API design expert. Review or design the following API:

```
{api_spec}
```

{context}

Provide recommendations for:
- RESTful conventions
- Error handling
- Versioning
- Authentication
- Documentation"""

SECURITY_REVIEW = """You are a security expert. Perform a security review of the following code:

```
{code}
```

Check for:
- Injection vulnerabilities (SQL, XSS, command)
- Authentication/authorization flaws
- Sensitive data exposure
- Insecure dependencies
- Input validation issues

Rate each finding by severity and provide remediation steps."""

SQL_OPTIMIZE = """You are a database performance expert. Optimize the following SQL query:

```sql
{query}
```

Schema context:
{schema}

Provide:
1. Optimized query
2. Explanation of changes
3. Index recommendations"""

README_GEN = """Generate a professional README.md for the following project:

Project name: {project_name}
Description: {description}

Source files summary:
```
{source_summary}
```

Include: installation, usage, configuration, and license sections."""

TYPE_HINTS = """Add comprehensive Python type hints to the following code.
Use modern Python 3.10+ syntax (e.g., list[str], X | None).

```
{code}
```

Return only the typed code with no explanation."""

REGEX_BUILD = """Build a regular expression for the following requirement:

Requirement: {requirement}

Test cases that should match: {match_cases}
Test cases that should NOT match: {no_match_cases}

Provide the regex pattern and a brief explanation."""

LOG_ANALYSIS = """Analyze the following log output and identify issues:

```
{logs}
```

Provide:
1. Summary of events
2. Errors and warnings found
3. Root cause hypotheses
4. Recommended actions"""

REFACTOR = """Refactor the following code to improve {goal}:

```
{code}
```

Maintain the same functionality. Explain key changes made."""

EXPLAIN_CODE = """Explain the following code clearly for a developer:

Language: {language}

```
{code}
```

Cover: purpose, how it works, key patterns, and potential gotchas."""

GENERATE_TESTS = """Generate comprehensive unit tests for the following code:

Framework: {framework}

```
{code}
```

Include edge cases, error handling, and descriptive test names."""
