"""Audit Pyright configuration for type-safety and insecure path settings."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.pyright(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
