"""Example: audit Dockerfiles with DevAI."""

from devai import DockerfileAnalyzer

analyzer = DockerfileAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
