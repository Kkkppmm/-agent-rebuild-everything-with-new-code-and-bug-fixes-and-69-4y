"""Example: audit Astral ty type checker configuration."""

from devai import TyAnalyzer

analyzer = TyAnalyzer(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
