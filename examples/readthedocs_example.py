"""Example: audit Read the Docs configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.readthedocs(".")
print(analyzer.summary())
print(analyzer.to_context())
