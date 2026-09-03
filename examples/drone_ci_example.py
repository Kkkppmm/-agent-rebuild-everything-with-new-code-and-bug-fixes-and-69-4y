"""Example: audit Drone CI pipelines with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.drone_ci(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
