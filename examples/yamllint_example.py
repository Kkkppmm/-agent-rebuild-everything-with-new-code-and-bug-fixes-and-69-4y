"""Example: audit yamllint configuration with DevAI."""

from devai import DevAI, YamllintAnalyzer

# Static analysis — no LLM required
analyzer = YamllintAnalyzer(".")
print(analyzer.summary())
print(analyzer.to_context())

# Via the DevAI facade
ai = DevAI.mock()
print(ai.yamllint(".").health_score())
