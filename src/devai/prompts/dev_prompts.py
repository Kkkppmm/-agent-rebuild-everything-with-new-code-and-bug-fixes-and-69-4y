"""Pre-built prompt templates for developer workflows."""

from devai.prompts.template import PromptTemplate

CODE_REVIEW = PromptTemplate(
  """You are an expert code reviewer. Review the following {language} code and provide:
1. A summary of what the code does
2. Potential bugs or issues
3. Performance concerns
4. Style and best-practice suggestions
5. Security considerations

```{language}
{code}
```

Be specific and actionable in your feedback.""",
  required=["language", "code"],
)

DEBUG = PromptTemplate(
  """You are a debugging expert. Help diagnose and fix this issue.

**Language:** {language}
**Error message:** {error}

**Code:**
```{language}
{code}
```

Provide:
1. Root cause analysis
2. Step-by-step fix
3. Prevention tips""",
  required=["language", "error", "code"],
)

COMMIT_MESSAGE = PromptTemplate(
  """Generate a clear, conventional commit message for these changes.

**Diff:**
```
{diff}
```

Format: <type>(<scope>): <subject>

Types: feat, fix, docs, style, refactor, test, chore
Keep the subject under 72 characters. Add a body if needed.""",
  required=["diff"],
)

API_DESIGN = PromptTemplate(
  """You are an API design expert. Review and improve this API design.

**Language/Framework:** {framework}
**Description:** {description}

**Current API:**
```
{api_spec}
```

Provide:
1. RESTful/idiomatic improvements
2. Naming conventions
3. Error handling recommendations
4. Documentation suggestions
5. Example usage""",
  required=["framework", "description", "api_spec"],
)

EXPLAIN_CODE = PromptTemplate(
  """Explain the following {language} code clearly for a developer.

```{language}
{code}
```

Cover:
1. High-level purpose
2. Key components and data flow
3. Non-obvious behavior
4. Time/space complexity (if applicable)""",
  required=["language", "code"],
)

UNIT_TEST = PromptTemplate(
  """Generate comprehensive unit tests for this {language} code using {framework}.

```{language}
{code}
```

Requirements:
- Cover happy path and edge cases
- Use descriptive test names
- Include setup/teardown if needed
- Mock external dependencies""",
  required=["language", "framework", "code"],
)

REFACTOR = PromptTemplate(
  """Refactor this {language} code to improve {goal}.

```{language}
{code}
```

Provide the refactored code with brief explanations of each change.""",
  required=["language", "goal", "code"],
)

DOCSTRING = PromptTemplate(
  """Generate docstrings for all public functions/classes in this {language} code.
Follow {style} docstring conventions.

```{language}
{code}
```

Return the complete code with docstrings added.""",
  required=["language", "style", "code"],
)

__all__ = [
  "API_DESIGN",
  "CODE_REVIEW",
  "COMMIT_MESSAGE",
  "DEBUG",
  "DOCSTRING",
  "EXPLAIN_CODE",
  "REFACTOR",
  "UNIT_TEST",
]
