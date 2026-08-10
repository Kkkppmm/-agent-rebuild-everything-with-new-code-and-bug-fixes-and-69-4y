"""Example: audit CircleCI configuration with DevAI."""

from devai import DevAI

ai = DevAI()
analyzer = ai.circleci(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze()[:5]:
    print(finding.format())
