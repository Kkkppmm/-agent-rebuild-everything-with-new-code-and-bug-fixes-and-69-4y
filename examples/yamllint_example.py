"""Example: audit yamllint configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.yamllint(".")
print(analyzer.summary())
print(analyzer.to_context())
