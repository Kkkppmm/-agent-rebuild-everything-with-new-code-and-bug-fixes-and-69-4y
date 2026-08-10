"""Example: audit Travis CI configs for security issues."""

from devai import TravisCIAnalyzer

analyzer = TravisCIAnalyzer(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
