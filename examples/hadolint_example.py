"""Example: audit Hadolint configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.hadolint(".")
print(analyzer.summary())
print(analyzer.to_context())
