"""Audit MkDocs documentation configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.mkdocs(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
