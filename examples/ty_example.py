"""Example: audit Astral ty type checker configuration."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.ty(".")
print(analyzer.summary())
print(analyzer.to_context())
