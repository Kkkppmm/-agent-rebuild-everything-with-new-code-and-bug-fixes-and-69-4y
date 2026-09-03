"""Audit AppVeyor CI configs for security issues."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.appveyor_ci(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
