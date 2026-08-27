"""Example: audit Codefresh pipelines with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.codefresh(".")
print(analyzer.summary())
print(analyzer.to_context())
