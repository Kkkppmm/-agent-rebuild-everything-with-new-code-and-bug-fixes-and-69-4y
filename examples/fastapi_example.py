"""Audit a FastAPI project for security risks."""

from devai import FastAPIAnalyzer

analyzer = FastAPIAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
