"""Example: audit golangci-lint configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.golangci(".")
print(analyzer.summary())
print(analyzer.to_context())
