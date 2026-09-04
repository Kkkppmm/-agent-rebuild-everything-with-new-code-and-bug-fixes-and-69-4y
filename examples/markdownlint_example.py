"""Example: audit markdownlint configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.markdownlint(".")
print(analyzer.summary())
print(analyzer.to_context())
