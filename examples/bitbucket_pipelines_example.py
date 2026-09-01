"""Audit Bitbucket Pipelines with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.bitbucket_pipelines(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
