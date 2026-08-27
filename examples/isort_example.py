"""Example: audit isort configuration with DevAI."""

from devai import DevAI, IsortAnalyzer

# Static analysis — no LLM required
analyzer = IsortAnalyzer(".")
print(analyzer.summary())
print(analyzer.to_context())

# Via the DevAI facade
ai = DevAI.mock()
print(ai.isort(".").health_score())
