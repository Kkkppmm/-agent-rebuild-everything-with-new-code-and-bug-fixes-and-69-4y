"""Example: audit CircleCI configuration with DevAI."""

from devai import CircleCIAnalyzer

analyzer = CircleCIAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
