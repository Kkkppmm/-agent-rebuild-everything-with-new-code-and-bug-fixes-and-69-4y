"""Example: audit Flake8 lint configuration with DevAI."""

from devai import DevAI, Flake8Analyzer

# Static analysis — no LLM required
analyzer = Flake8Analyzer(".")
print(analyzer.summary())
print(analyzer.to_context())

# Via the DevAI facade
ai = DevAI.mock()
print(ai.flake8(".").health_score())
