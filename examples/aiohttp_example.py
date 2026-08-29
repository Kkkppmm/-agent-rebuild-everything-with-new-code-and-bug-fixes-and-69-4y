"""Audit an aiohttp project for security risks."""

from devai import AiohttpAnalyzer

analyzer = AiohttpAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
