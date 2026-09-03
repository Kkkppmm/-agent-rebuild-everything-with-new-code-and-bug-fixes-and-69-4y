"""Example: audit Hugo documentation configs with DevAI."""

from devai import HugoAnalyzer

analyzer = HugoAnalyzer(".")
print(analyzer.summary())

for finding in analyzer.analyze():
    print(finding.format())

print(f"\nHealth score: {analyzer.health_score()}/100")
