"""Example: audit Vitest configs with VitestAnalyzer."""

from devai.vitest_analyzer import VitestAnalyzer

analyzer = VitestAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
