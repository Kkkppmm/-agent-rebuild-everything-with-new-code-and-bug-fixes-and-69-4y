"""Prompt templates for developer tasks."""

from __future__ import annotations

from dataclasses import dataclass
from string import Template


@dataclass
class PromptTemplate:
  name: str
  template: str
  description: str = ""

  def format(self, **kwargs: str) -> str:
    return Template(self.template).safe_substitute(**kwargs)

  def __call__(self, **kwargs: str) -> str:
    return self.format(**kwargs)


CODE_REVIEW = PromptTemplate(
  name="code_review",
  description="Review code for bugs, style, and improvements",
  template="""You are an expert code reviewer. Review the following code thoroughly.

Focus on:
- Bugs and logic errors
- Security vulnerabilities
- Performance issues
- Code style and readability
- Missing error handling

Code:
```$language
$code
```

Provide a structured review with severity levels (critical, warning, suggestion).""",
)

DEBUG = PromptTemplate(
  name="debug",
  description="Debug code given an error message",
  template="""You are an expert debugger. Analyze the code and error, then provide a fix.

Code:
```$language
$code
```

Error:
$error

Provide:
1. Root cause analysis
2. Fixed code
3. Explanation of the fix""",
)

EXPLAIN = PromptTemplate(
  name="explain",
  description="Explain code in plain language",
  template="""Explain the following code clearly for a developer.

```$language
$code
```

Cover: purpose, how it works, key patterns, and any gotchas.""",
)

REFACTOR = PromptTemplate(
  name="refactor",
  description="Suggest refactoring improvements",
  template="""Refactor the following code for better readability, maintainability, and performance.

```$language
$code
```

Provide the refactored code with explanations for each change.""",
)

GENERATE_TESTS = PromptTemplate(
  name="generate_tests",
  description="Generate unit tests for code",
  template="""Generate comprehensive unit tests for the following code.

```$language
$code
```

Use pytest. Cover edge cases, error paths, and happy paths.""",
)

SECURITY_REVIEW = PromptTemplate(
  name="security_review",
  description="Security-focused code review",
  template="""Perform a security review of this code. Check for OWASP Top 10 vulnerabilities,
injection attacks, auth issues, data exposure, and insecure dependencies.

```$language
$code
```

Report findings by severity with remediation steps.""",
)

COMMIT_MESSAGE = PromptTemplate(
  name="commit_message",
  description="Generate a commit message from a diff",
  template="""Generate a concise, conventional commit message for this diff.

Diff:
```
$diff
```

Format: type(scope): description

Types: feat, fix, refactor, test, docs, chore""",
)

API_DESIGN = PromptTemplate(
  name="api_design",
  description="Review or design an API",
  template="""Review this API design for RESTful best practices, naming, versioning,
error handling, and developer experience.

```
$api_spec
```

Provide specific recommendations.""",
)

SQL_OPTIMIZE = PromptTemplate(
  name="sql_optimize",
  description="Optimize SQL queries",
  template="""Analyze and optimize this SQL query.

```sql
$query
```

Schema context:
$schema

Suggest indexes, rewrites, and explain performance implications.""",
)

README_GEN = PromptTemplate(
  name="readme_gen",
  description="Generate README documentation",
  template="""Generate a professional README.md for this project.

Project name: $project_name
Description: $description
Key features: $features
Tech stack: $tech_stack

Include: installation, usage, configuration, and license sections.""",
)

TYPE_HINTS = PromptTemplate(
  name="type_hints",
  description="Add type hints to Python code",
  template="""Add complete type hints to this Python code.

```python
$code
```

Use modern Python 3.10+ syntax (X | Y, list[str], etc.).""",
)

REGEX_BUILD = PromptTemplate(
  name="regex_build",
  description="Build a regex from a description",
  template="""Build a regex pattern for this requirement:

Description: $description
Test cases that should match: $match_cases
Test cases that should NOT match: $no_match_cases

Provide the regex with explanation and Python usage example.""",
)

LOG_ANALYSIS = PromptTemplate(
  name="log_analysis",
  description="Analyze application logs",
  template="""Analyze these application logs and identify issues.

```
$logs
```

Report: errors, warnings, patterns, root causes, and recommended actions.""",
)

DOCSTRING_GEN = PromptTemplate(
  name="docstring_gen",
  description="Generate docstrings for functions",
  template="""Add Google-style docstrings to all functions in this code.

```python
$code
```

Return the complete code with docstrings.""",
)

ALL_TEMPLATES: dict[str, PromptTemplate] = {
  t.name: t
  for t in [
    CODE_REVIEW,
    DEBUG,
    EXPLAIN,
    REFACTOR,
    GENERATE_TESTS,
    SECURITY_REVIEW,
    COMMIT_MESSAGE,
    API_DESIGN,
    SQL_OPTIMIZE,
    README_GEN,
    TYPE_HINTS,
    REGEX_BUILD,
    LOG_ANALYSIS,
    DOCSTRING_GEN,
  ]
}
