"""Pre-built prompt templates for common developer tasks."""

from devai.prompts.template import PromptTemplate

CODE_REVIEW = PromptTemplate(
    """You are an expert code reviewer. Review the following {language} code and provide:
1. A summary of what the code does
2. Potential bugs or issues
3. Performance concerns
4. Style and best-practice suggestions
5. A severity rating (low/medium/high) for each issue

```{language}
{code}
```

Focus on actionable feedback. Be concise but thorough."""
)

DEBUG = PromptTemplate(
    """You are a debugging expert. Help diagnose and fix the following issue.

**Language:** {language}
**Error message:**
```
{error}
```

**Code:**
```{language}
{code}
```

**Context:** {context}

Provide:
1. Root cause analysis
2. Step-by-step fix
3. Fixed code
4. How to prevent this in the future"""
)

COMMIT_MESSAGE = PromptTemplate(
    """Generate a clear, conventional commit message for the following diff.

Follow Conventional Commits format (type(scope): description).

```
{diff}
```

Return only the commit message, no explanation."""
)

API_DESIGN = PromptTemplate(
    """You are an API design expert. Design a REST API for the following requirement:

**Requirement:** {requirement}
**Tech stack:** {stack}

Provide:
1. Endpoint list with methods, paths, and descriptions
2. Request/response schemas (JSON)
3. Error handling strategy
4. Authentication approach
5. Example curl commands"""
)

REFACTOR = PromptTemplate(
    """Refactor the following {language} code to improve {goal}.

```{language}
{code}
```

Provide:
1. Explanation of changes
2. Refactored code
3. Trade-offs of your approach"""
)

EXPLAIN_CODE = PromptTemplate(
    """Explain the following {language} code clearly for a {audience} developer.

```{language}
{code}
```

Cover:
1. High-level purpose
2. Key components and data flow
3. Non-obvious patterns or tricks
4. Potential improvements"""
)

WRITE_TESTS = PromptTemplate(
    """Write comprehensive {framework} tests for the following {language} code.

```{language}
{code}
```

Include:
- Happy path tests
- Edge cases
- Error handling tests
- Use descriptive test names"""
)

DOCSTRING = PromptTemplate(
    """Write clear docstrings for the following {language} code following {style} conventions.

```{language}
{code}
```

Return the complete code with docstrings added. Do not change the logic."""
)
