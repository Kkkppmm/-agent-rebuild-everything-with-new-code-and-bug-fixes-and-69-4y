"""Example: audit Black formatter configuration with DevAI."""

from devai import BlackAnalyzer, DevAI

# Static analysis — no LLM required
analyzer = BlackAnalyzer(".")
print(analyzer.summary())
print(analyzer.to_context())

# Via the DevAI facade
ai = DevAI.mock()
print(ai.black(".").health_score())
