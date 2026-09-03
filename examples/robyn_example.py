"""Audit a Robyn project for security risks."""

from devai import RobynAnalyzer

analyzer = RobynAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
