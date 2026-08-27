"""Audit isort configuration for import hygiene and Black compatibility."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.isort(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
