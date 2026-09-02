"""Example: audit PEP 723 inline script metadata blocks."""

from devai import Pep723Analyzer

analyzer = Pep723Analyzer(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
