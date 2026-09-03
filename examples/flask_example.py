"""Audit a Flask project for security risks."""

from devai import FlaskAnalyzer

analyzer = FlaskAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
