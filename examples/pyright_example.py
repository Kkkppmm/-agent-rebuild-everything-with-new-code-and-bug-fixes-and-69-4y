"""Example: audit Pyright configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.pyright(".")
print(analyzer.summary())
print(analyzer.to_context())
