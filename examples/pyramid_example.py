"""Audit a Pyramid project for security risks."""

from devai import PyramidAnalyzer

analyzer = PyramidAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
