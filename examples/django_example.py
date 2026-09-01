"""Audit a Django project for security risks."""

from devai import DjangoAnalyzer

analyzer = DjangoAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
