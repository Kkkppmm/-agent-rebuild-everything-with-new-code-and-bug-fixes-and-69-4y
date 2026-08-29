"""Example: audit a FastAPI application with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.fastapi(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")
for finding in analyzer.analyze():
    print(finding.format())
