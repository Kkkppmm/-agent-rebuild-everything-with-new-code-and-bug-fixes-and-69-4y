"""Example: audit Woodpecker CI pipelines with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.woodpecker_ci(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
