"""Audit pylint configuration for security and linting hygiene risks."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.pylint(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
