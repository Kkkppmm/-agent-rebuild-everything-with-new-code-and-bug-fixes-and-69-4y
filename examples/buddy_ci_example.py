"""Example: audit Buddy CI pipelines with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.buddy_ci(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
