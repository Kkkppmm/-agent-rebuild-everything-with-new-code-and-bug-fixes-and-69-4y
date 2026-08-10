"""Example: audit Azure Pipelines configuration with DevAI."""

from devai import DevAI

ai = DevAI()
analyzer = ai.azure_pipelines(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze()[:5]:
    print(finding.format())
