"""Example: audit Jenkins pipelines with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.jenkins(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
