"""Audit GitLab CI pipelines with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.gitlab_ci(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
