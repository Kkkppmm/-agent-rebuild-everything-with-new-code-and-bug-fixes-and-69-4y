"""Prompt templates for developer tasks."""

from __future__ import annotations

from dataclasses import dataclass
from string import Template


@dataclass
class PromptTemplate:
  """Simple string template with variable substitution."""

  template: str

  def format(self, **kwargs: str) -> str:
    return Template(self.template).safe_substitute(**kwargs)

  def __call__(self, **kwargs: str) -> str:
    return self.format(**kwargs)


CODE_REVIEW = PromptTemplate("""You are an expert code reviewer. Review the following code and provide:
1. Summary of what the code does
2. Issues (bugs, edge cases, performance)
3. Style and maintainability suggestions
4. Security concerns if any
5. Overall rating (1-10) with justification

Code:
```$language
$code
```

Provide actionable, specific feedback.""")

DEBUG = PromptTemplate("""You are an expert debugger. Help fix this error.

Error:
$error

Code:
```$language
$code
```

Provide:
1. Root cause analysis
2. Step-by-step fix
3. Corrected code
4. How to prevent this in the future""")

EXPLAIN = PromptTemplate("""You are a patient senior engineer. Explain the following code clearly.

Code:
```$language
$code
```

Cover: purpose, how it works, key concepts, and potential gotchas.""")

REFACTOR = PromptTemplate("""You are a refactoring expert. Improve this code.

Goal: $goal

Code:
```$language
$code
```

Provide refactored code with explanation of changes.""")

SECURITY_REVIEW = PromptTemplate("""You are a security engineer. Audit this code for vulnerabilities.

Code:
```$language
$code
```

Check for: injection, auth issues, data exposure, insecure defaults, dependency risks.
Rate severity and provide fixes.""")

TEST_GENERATION = PromptTemplate("""You are a test engineer. Write comprehensive tests for this code.

Framework: $framework

Code:
```$language
$code
```

Include edge cases, error paths, and clear test names.""")

DOCSTRING_GEN = PromptTemplate("""Generate docstrings for this code following $style conventions.

Code:
```$language
$code
```

Return the code with docstrings added.""")

COMMIT_MESSAGE = PromptTemplate("""Generate a concise, conventional commit message for this diff.

Diff:
```
$diff
```

Format: type(scope): description

Types: feat, fix, refactor, docs, test, chore""")

API_DESIGN = PromptTemplate("""You are an API design expert. Review or design this API.

Context:
$context

Requirements:
$requirements

Provide endpoint design, request/response schemas, error handling, and versioning advice.""")

SQL_OPTIMIZE = PromptTemplate("""You are a database performance expert. Optimize this SQL query.

Database: $database

Query:
```sql
$query
```

Schema context:
$schema

Provide optimized query, index recommendations, and explanation.""")

README_GEN = PromptTemplate("""Generate a professional README for this project.

Project name: $name
Description: $description
Tech stack: $stack
Key features: $features

Include: installation, usage, configuration, and license sections.""")

TYPE_HINTS = PromptTemplate("""Add complete type hints to this Python code.

Code:
```python
$code
```

Use modern Python 3.10+ syntax (X | Y, built-in generics).""")

REGEX_BUILD = PromptTemplate("""Build a regex for this requirement.

Requirement: $requirement
Test cases (should match): $positive
Test cases (should not match): $negative

Provide the regex with explanation and Python usage example.""")

LOG_ANALYSIS = PromptTemplate("""Analyze these application logs and identify issues.

Logs:
```
$logs
```

Provide: timeline, errors found, root cause hypothesis, and recommended actions.""")

DIRECTORY_REVIEW = PromptTemplate("""Review this codebase structure and files.

Directory: $directory

Files:
$files

Provide architecture assessment, code quality observations, and improvement recommendations.""")
