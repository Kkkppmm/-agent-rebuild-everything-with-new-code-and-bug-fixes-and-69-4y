"""Example: audit a Bottle app for security risks."""

from devai import BottleAnalyzer

analyzer = BottleAnalyzer(".")
print(analyzer.summary())

for finding in analyzer.analyze():
    print(finding.format())
