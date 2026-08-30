"""Audit a Starlette project for security risks."""

from devai import StarletteAnalyzer

analyzer = StarletteAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
