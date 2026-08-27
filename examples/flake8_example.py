"""Audit Flake8 configuration for linting hygiene and security rule coverage."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.flake8(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
