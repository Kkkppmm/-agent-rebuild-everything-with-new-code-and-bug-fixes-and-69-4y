"""Example: audit PEP 723 inline script metadata blocks."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.pep723(".")
print(analyzer.summary())
print(analyzer.to_context())
