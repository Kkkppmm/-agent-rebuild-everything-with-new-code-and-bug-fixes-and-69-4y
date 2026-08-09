"""Example: audit GitLab CI configuration with DevAI."""

from devai import GitLabCIAnalyzer

analyzer = GitLabCIAnalyzer(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze():
    print(finding.format())
