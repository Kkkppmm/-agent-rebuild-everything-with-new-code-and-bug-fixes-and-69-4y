"""Audit AWS CodePipeline configs with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.aws_codepipeline(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
