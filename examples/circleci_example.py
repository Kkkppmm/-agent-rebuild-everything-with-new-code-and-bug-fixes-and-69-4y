"""Audit CircleCI configs with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.circleci(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
