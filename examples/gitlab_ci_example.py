"""Example: audit GitLab CI configuration with DevAI."""

from devai import DevAI

ai = DevAI()
analyzer = ai.gitlab_ci(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze()[:5]:
    print(finding.format())
