"""Example: audit Harness CI pipelines with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.harness_ci(".")
print(analyzer.summary())
print(analyzer.to_context())
