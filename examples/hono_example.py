"""Example: audit a Hono application for security issues."""

from devai import HonoAnalyzer

analyzer = HonoAnalyzer(".")
print(analyzer.summary())

for finding in analyzer.analyze():
    print(finding.format())

print(f"\nHealth score: {analyzer.health_score()}/100")
