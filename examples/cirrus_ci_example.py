"""Example: audit Cirrus CI pipelines with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.cirrus_ci(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
