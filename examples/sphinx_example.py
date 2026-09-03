"""Example: audit Sphinx documentation configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.sphinx(".")
print(analyzer.summary())
print(analyzer.to_context())
