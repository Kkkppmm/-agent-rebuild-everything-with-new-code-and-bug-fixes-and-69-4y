"""Example: audit Trivy ignore files and CLI configs with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.trivy(".")
print(analyzer.summary())
print(analyzer.to_context())
