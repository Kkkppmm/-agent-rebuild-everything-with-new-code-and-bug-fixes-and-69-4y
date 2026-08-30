"""Example: audit Deno configs with DenoAnalyzer."""

from devai.deno_analyzer import DenoAnalyzer

analyzer = DenoAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
