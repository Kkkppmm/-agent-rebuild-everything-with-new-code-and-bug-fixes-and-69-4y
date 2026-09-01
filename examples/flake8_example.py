"""Example: audit Flake8 configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.flake8(".")
print(analyzer.summary())
print(analyzer.to_context())
