"""Example: audit Makefiles with DevAI."""

from devai import MakefileAnalyzer

analyzer = MakefileAnalyzer(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
