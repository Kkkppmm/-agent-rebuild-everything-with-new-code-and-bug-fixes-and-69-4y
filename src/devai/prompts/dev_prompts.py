"""Developer-focused prompt templates."""

CODE_REVIEW = """Review the following code for bugs, style issues, and improvements.
Provide specific, actionable feedback.

Code:
```
{code}
```

Language: {language}

Respond with:
1. Summary (1-2 sentences)
2. Issues found (with line references if possible)
3. Suggested improvements
4. Overall rating: PASS / NEEDS_WORK / CRITICAL"""

DEBUG = """Help debug the following issue.

Error/Issue:
{error}

Code context:
```
{code}
```

Provide:
1. Root cause analysis
2. Step-by-step fix
3. Prevention tips"""

COMMIT_MESSAGE = """Generate a concise, conventional commit message for this diff.

Diff:
```
{diff}
```

Format: type(scope): description
Types: feat, fix, docs, style, refactor, test, chore
Keep the subject under 72 characters. Add a body if needed."""

API_DESIGN = """Review this API design for REST/HTTP best practices.

API specification:
```
{spec}
```

Evaluate:
1. Resource naming and URL structure
2. HTTP method usage
3. Request/response schemas
4. Error handling
5. Authentication/authorization considerations
6. Specific recommendations"""

SECURITY_REVIEW = """Perform a security review of this code.

Code:
```
{code}
```

Check for:
- Injection vulnerabilities (SQL, XSS, command)
- Authentication/authorization flaws
- Sensitive data exposure
- Insecure dependencies or configurations
- OWASP Top 10 issues

Rate severity: LOW / MEDIUM / HIGH / CRITICAL for each finding."""

SQL_OPTIMIZE = """Optimize this SQL query for performance.

Query:
```sql
{query}
```

Schema context (if available):
{schema}

Provide:
1. Performance analysis
2. Optimized query
3. Index recommendations
4. Estimated improvement explanation"""

README_GEN = """Generate a README.md for this project.

Project info:
{info}

Source files summary:
{files}

Include: title, description, installation, usage, configuration, and license sections.
Use markdown formatting."""

TYPE_HINTS = """Add comprehensive Python type hints to this code.

Code:
```python
{code}
```

Requirements:
- Use modern Python 3.10+ syntax (e.g. list[str], not List[str])
- Add return type annotations
- Use Optional/Union only when necessary
- Include docstrings for public functions"""

REGEX_BUILD = """Build a regex pattern for this requirement.

Requirement: {requirement}

Examples that should match: {matches}
Examples that should NOT match: {non_matches}

Provide:
1. The regex pattern
2. Explanation of each part
3. Python usage example with re module
4. Edge cases to watch for"""

LOG_ANALYSIS = """Analyze these application logs and identify issues.

Logs:
```
{logs}
```

Provide:
1. Timeline of events
2. Errors and warnings summary
3. Root cause hypothesis
4. Recommended actions"""

REFACTOR = """Refactor this code for better readability, maintainability, and performance.

Code:
```
{code}
```

Goals: {goals}

Provide:
1. Refactored code
2. Explanation of changes
3. Trade-offs considered"""

EXPLAIN_CODE = """Explain this code clearly for a developer.

Code:
```
{code}
```

Language: {language}

Cover:
1. What it does (high level)
2. How it works (step by step)
3. Key patterns or algorithms used
4. Potential issues or improvements"""

TEST_GEN = """Generate unit tests for this code.

Code:
```python
{code}
```

Framework: {framework}

Include:
- Happy path tests
- Edge cases
- Error handling tests
- Use descriptive test names"""

DOCSTRING_GEN = """Generate comprehensive docstrings for this code.

Code:
```python
{code}
```

Style: {style}

Requirements:
- Use Google-style docstrings unless otherwise specified
- Document all public functions, classes, and methods
- Include Args, Returns, and Raises sections where applicable
- Add module-level docstring if missing
- Return the complete code with docstrings added"""
