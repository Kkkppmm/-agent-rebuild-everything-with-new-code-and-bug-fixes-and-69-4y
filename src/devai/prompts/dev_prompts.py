"""Ready-made prompt templates for developer tasks."""

from devai.prompts.templates import PromptTemplate

CODE_REVIEW = PromptTemplate(
    """You are an expert code reviewer. Review the following code and provide:
1. Summary of what the code does
2. Issues (bugs, logic errors, edge cases)
3. Style and best practice suggestions
4. Security concerns if any

Code:
```$language
$code
```

Provide actionable, specific feedback."""
)

DEBUG = PromptTemplate(
    """You are a debugging expert. Analyze the code and error, then provide:
1. Root cause analysis
2. Step-by-step fix
3. Corrected code

Code:
```$language
$code
```

Error:
```
$error
```

$context"""
)

EXPLAIN = PromptTemplate(
    """You are a patient programming teacher. Explain the following code clearly:
1. What it does (high level)
2. How it works (step by step)
3. Key concepts used

Code:
```$language
$code
```"""
)

REFACTOR = PromptTemplate(
    """You are a refactoring expert. Improve the following code for readability,
maintainability, and performance. Show the refactored code with brief explanations.

Code:
```$language
$code
```

Goals: $goals"""
)

SECURITY_REVIEW = PromptTemplate(
    """You are a security engineer. Review this code for vulnerabilities:
- Injection attacks (SQL, command, XSS)
- Authentication/authorization issues
- Data exposure
- Input validation gaps
- Dependency risks

Code:
```$language
$code
```

Rate severity (critical/high/medium/low) for each finding."""
)

COMMIT_MESSAGE = PromptTemplate(
    """Generate a concise, conventional commit message for this diff.
Use format: type(scope): description

Diff:
```
$diff
```"""
)

TEST_GENERATION = PromptTemplate(
    """Generate comprehensive unit tests for the following code.
Use $framework framework. Cover edge cases and error paths.

Code:
```$language
$code
```"""
)

API_DESIGN = PromptTemplate(
    """You are an API design expert. Review or design an API based on:

Description: $description

Requirements:
$requirements

Provide RESTful endpoint design with request/response schemas."""
)

SQL_OPTIMIZE = PromptTemplate(
    """You are a database performance expert. Optimize this SQL query:

```sql
$query
```

Schema context:
$schema

Provide the optimized query and explain the improvements."""
)

README_GEN = PromptTemplate(
    """Generate a professional README.md for this project:

Project name: $name
Description: $description
Features: $features
Tech stack: $stack"""
)

TYPE_HINTS = PromptTemplate(
    """Add complete Python type hints to this code. Preserve behavior.

```python
$code
```"""
)

REGEX_BUILD = PromptTemplate(
    """Build a regex pattern for: $description

Test cases that should match: $positive
Test cases that should NOT match: $negative

Provide the regex with explanation."""
)

LOG_ANALYSIS = PromptTemplate(
    """Analyze these application logs and identify:
1. Errors and their likely causes
2. Performance issues
3. Recommended actions

Logs:
```
$logs
```"""
)

AGENT_SYSTEM = PromptTemplate(
    """You are a coding agent with access to tools. Complete the user's task
by reasoning step by step and using available tools when needed.

Available tools: $tools"""
)

RAG_QUERY = PromptTemplate(
    """Answer the question using only the provided context. If the context
doesn't contain enough information, say so.

Context:
$context

Question: $question"""
)
