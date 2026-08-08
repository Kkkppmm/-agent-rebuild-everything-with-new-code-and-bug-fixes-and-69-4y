"""Audit pre-commit configuration for unpinned hooks and unsafe entries."""

from devai import DevAI

ai = DevAI()
analyzer = ai.precommit(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:10]:
    print(finding.format())
