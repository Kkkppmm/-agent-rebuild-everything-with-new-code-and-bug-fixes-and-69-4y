"""Example: audit actionlint configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.actionlint(".")
print(analyzer.summary())
print(analyzer.to_context())
