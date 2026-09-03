"""Example: audit Pelican documentation configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.pelican(".")
print(analyzer.summary())
print(analyzer.to_context())
