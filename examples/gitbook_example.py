"""Example: audit GitBook documentation configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.gitbook(".")
print(analyzer.summary())
print(analyzer.to_context())
