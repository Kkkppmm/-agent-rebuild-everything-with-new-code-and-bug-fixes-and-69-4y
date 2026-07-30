"""DevAI developer tools — unified static analysis facade."""

from devai import DevTools

# One-line project health check
tools = DevTools(".")
print(tools.summary())

# Or get LLM-ready context for AI-assisted review
context = tools.to_context()
print(context[:500])

# Access individual analyzers
print(tools.imports.summary())
print(tools.secrets.summary())
print(tools.typing.summary())
print(tools.docstrings.summary())
print(tools.deps.summary())

# Generate changelog from git history
commits = tools.collect_changelog(max_count=20)
print(tools.format_changelog(commits, version="3.5.0"))
