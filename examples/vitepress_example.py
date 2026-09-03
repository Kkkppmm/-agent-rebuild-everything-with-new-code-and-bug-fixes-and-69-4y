"""Example: audit VitePress documentation configs with DevAI."""

from devai import VitePressAnalyzer

analyzer = VitePressAnalyzer(".")
print(analyzer.summary())

for finding in analyzer.analyze():
    print(finding.format())

print(f"\nHealth score: {analyzer.health_score()}/100")
