"""Example: audit turbo.json and turbo.jsonc with TurboAnalyzer."""

from devai.turbo_analyzer import TurboAnalyzer

analyzer = TurboAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
