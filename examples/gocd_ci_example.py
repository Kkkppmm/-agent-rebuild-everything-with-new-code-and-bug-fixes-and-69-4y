"""Example: audit GoCD pipelines with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.gocd_ci(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
