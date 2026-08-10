"""Example: audit Jenkins pipeline files with DevAI."""

from devai import JenkinsfileAnalyzer

analyzer = JenkinsfileAnalyzer(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze():
    print(finding.format())
