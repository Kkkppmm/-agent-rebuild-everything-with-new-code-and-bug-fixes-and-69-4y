"""Prompt templates for developer tasks."""

from __future__ import annotations

from dataclasses import dataclass
from string import Template


@dataclass
class PromptTemplate:
    """A template with variable substitution."""

    template: str

    def format(self, **kwargs: str) -> str:
        return Template(self.template).safe_substitute(**kwargs)


CODE_REVIEW = PromptTemplate(
    """You are an expert code reviewer. Review the following code and provide:
1. Summary of what the code does
2. Issues (bugs, edge cases, performance)
3. Suggestions for improvement
4. Security concerns if any

Code:
```$language
$code
```

Provide a thorough but concise review."""
)

EXPLAIN_CODE = PromptTemplate(
    """Explain the following code clearly for a developer. Cover:
- Purpose and behavior
- Key logic and data flow
- Important edge cases

```$language
$code
```"""
)

DEBUG_CODE = PromptTemplate(
    """You are a debugging expert. Analyze this code and error to find the root cause and fix.

Code:
```$language
$code
```

Error:
$error

Provide:
1. Root cause analysis
2. Step-by-step fix
3. Corrected code snippet"""
)

REFACTOR_CODE = PromptTemplate(
    """Refactor the following code for better readability, maintainability, and performance.
Explain what you changed and why.

```$language
$code
```

Goals: $goals"""
)

SECURITY_REVIEW = PromptTemplate(
    """Perform a security review of this code. Check for:
- Injection vulnerabilities
- Authentication/authorization issues
- Data exposure
- Input validation gaps
- Insecure dependencies or patterns

```$language
$code
```"""
)

GENERATE_TESTS = PromptTemplate(
    """Generate comprehensive unit tests for this code using $framework.
Include edge cases and error scenarios.

```$language
$code
```"""
)

COMMIT_MESSAGE = PromptTemplate(
    """Generate a clear, conventional commit message for these changes.

Diff:
```
$diff
```

Format: type(scope): description

Then a blank line and detailed body if needed."""
)

API_DESIGN = PromptTemplate(
    """Review and improve this API design. Consider RESTful conventions, naming, versioning, and error handling.

```$language
$code
```"""
)

SQL_OPTIMIZE = PromptTemplate(
    """Analyze and optimize this SQL query. Suggest indexes and rewrite if needed.

```sql
$query
```

Context: $context"""
)

README_GEN = PromptTemplate(
    """Generate a README.md for this project based on the code and description.

Project: $project_name
Description: $description

Key files:
$files"""
)

TYPE_HINTS = PromptTemplate(
    """Add complete type hints to this Python code. Return the fully typed version.

```python
$code
```"""
)

REGEX_BUILD = PromptTemplate(
    """Build a regex pattern for this requirement. Explain each part.

Requirement: $requirement
Test cases that should match: $match_cases
Test cases that should NOT match: $no_match_cases"""
)

LOG_ANALYSIS = PromptTemplate(
    """Analyze these application logs and identify issues, patterns, and recommended actions.

```
$logs
```

Context: $context"""
)
