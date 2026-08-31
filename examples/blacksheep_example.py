"""Audit a BlackSheep project for security risks."""

from devai import BlacksheepAnalyzer

analyzer = BlacksheepAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
