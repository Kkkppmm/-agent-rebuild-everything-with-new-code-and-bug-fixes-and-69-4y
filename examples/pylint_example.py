"""Example: audit pylint configuration with DevAI."""

from devai import DevAI, PylintAnalyzer

# Static analysis — no LLM required
analyzer = PylintAnalyzer(".")
print(analyzer.summary())
print(analyzer.to_context())

# Via the DevAI facade
ai = DevAI.mock()
print(ai.pylint(".").health_score())
