"""Example: audit .gitignore coverage with DevAI."""

from devai import GitignoreAnalyzer

analyzer = GitignoreAnalyzer(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
