"""Example: audit Jest configuration with JestAnalyzer."""

from devai.jest_analyzer import JestAnalyzer

analyzer = JestAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
