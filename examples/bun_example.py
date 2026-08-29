"""Example: audit Bun configs with BunAnalyzer."""

from devai.bun_analyzer import BunAnalyzer

analyzer = BunAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
