"""Example: audit pre-commit configuration with DevAI."""

from devai import PrecommitAnalyzer

analyzer = PrecommitAnalyzer(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
