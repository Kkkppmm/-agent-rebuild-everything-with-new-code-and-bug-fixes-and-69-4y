"""Example: audit package.json and .npmrc with NpmAnalyzer."""

from devai.npm_analyzer import NpmAnalyzer

analyzer = NpmAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
