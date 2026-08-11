"""Audit GoCD pipeline configs with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.gocd_ci(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:10]:
    print(finding.format())
