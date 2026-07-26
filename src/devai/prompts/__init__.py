"""Prompt templates for developer tasks."""

from __future__ import annotations

from dataclasses import dataclass
from string import Template
from typing import Any


@dataclass
class PromptTemplate:
    """A reusable prompt template with variable substitution."""

    template: str
    system: str | None = None

    def format(self, **kwargs: Any) -> str:
        return Template(self.template).safe_substitute(**kwargs)

    def to_messages(self, **kwargs: Any) -> list[dict[str, str]]:
        messages = []
        if self.system:
            messages.append({"role": "system", "content": Template(self.system).safe_substitute(**kwargs)})
        messages.append({"role": "user", "content": self.format(**kwargs)})
        return messages


CODE_REVIEW = PromptTemplate(
    system="You are an expert code reviewer. Provide constructive, actionable feedback.",
    template="""Review the following code for bugs, style issues, performance problems, and best practices.

Language: ${language}

```
${code}
```

Provide:
1. Summary of issues found
2. Specific line-by-line feedback
3. Suggested improvements""",
)

DEBUG = PromptTemplate(
    system="You are an expert debugger. Analyze errors systematically and provide clear solutions.",
    template="""Help debug the following issue:

Error:
```
${error}
```

${code_section}

Provide:
1. Root cause analysis
2. Step-by-step fix
3. Prevention tips""",
)

COMMIT_MESSAGE = PromptTemplate(
    system="You write clear, conventional commit messages.",
    template="""Generate a conventional commit message for this diff:

```
${diff}
```

Format: <type>(<scope>): <description>

Types: feat, fix, docs, style, refactor, test, chore""",
)

API_DESIGN = PromptTemplate(
    system="You are an API design expert following REST and OpenAPI best practices.",
    template="""Design an API for the following requirement:

${requirement}

Provide:
1. Endpoint definitions (method, path, description)
2. Request/response schemas
3. Error handling
4. Authentication approach""",
)

SECURITY_REVIEW = PromptTemplate(
    system="You are a security expert specializing in application security.",
    template="""Perform a security review of the following code:

```
${code}
```

Check for:
- Injection vulnerabilities (SQL, XSS, command injection)
- Authentication/authorization flaws
- Sensitive data exposure
- Insecure dependencies
- Input validation issues

Provide severity ratings (Critical/High/Medium/Low) for each finding.""",
)

SQL_OPTIMIZE = PromptTemplate(
    system="You are a database performance expert.",
    template="""Optimize the following SQL query:

```sql
${query}
```

Schema context:
${schema}

Provide:
1. Performance analysis
2. Optimized query
3. Index recommendations""",
)

README_GEN = PromptTemplate(
    system="You write clear, comprehensive README files for open-source projects.",
    template="""Generate a README for a project with these details:

Project name: ${name}
Description: ${description}
Language: ${language}
Features: ${features}

Include: installation, usage, configuration, and contributing sections.""",
)

TYPE_HINTS = PromptTemplate(
    system="You are a Python typing expert.",
    template="""Add comprehensive type hints to the following Python code:

```python
${code}
```

Use modern Python 3.10+ syntax (e.g., `list[str]` instead of `List[str]`).
Add return types and parameter types. Do not change the logic.""",
)

REGEX_BUILD = PromptTemplate(
    system="You are a regex expert who writes clear, well-tested patterns.",
    template="""Create a regex pattern for:

${description}

Provide:
1. The regex pattern
2. Explanation of each part
3. Test cases (matching and non-matching examples)""",
)

LOG_ANALYSIS = PromptTemplate(
    system="You are a DevOps expert skilled at log analysis.",
    template="""Analyze the following logs and identify issues:

```
${logs}
```

Provide:
1. Timeline of events
2. Errors and warnings found
3. Root cause hypothesis
4. Recommended actions""",
)

REFACTOR = PromptTemplate(
    system="You are a refactoring expert who improves code quality without changing behavior.",
    template="""Refactor the following code to improve readability, maintainability, and performance:

```
${code}
```

Goals: ${goals}

Provide:
1. Refactored code
2. Explanation of changes
3. Any trade-offs""",
)

TEST_GEN = PromptTemplate(
    system="You write thorough unit tests using pytest.",
    template="""Generate unit tests for the following code:

```python
${code}
```

Requirements:
- Use pytest
- Cover edge cases and error paths
- Use descriptive test names
- Include fixtures where appropriate""",
)

EXPLAIN_CODE = PromptTemplate(
    system="You explain code clearly for developers of all skill levels.",
    template="""Explain the following code:

Language: ${language}

```
${code}
```

Cover:
1. What it does (high-level)
2. How it works (step by step)
3. Key patterns or techniques used""",
)
