"""Audit a Litestar project for security risks."""

from devai import LitestarAnalyzer

analyzer = LitestarAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
