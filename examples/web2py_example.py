"""Audit a web2py project for security risks."""

from devai import Web2pyAnalyzer

analyzer = Web2pyAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
