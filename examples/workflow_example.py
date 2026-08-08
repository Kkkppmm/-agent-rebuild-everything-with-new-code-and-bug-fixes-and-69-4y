"""Audit GitHub Actions workflows for CI security issues."""

from devai import DevAI

ai = DevAI()
analyzer = ai.workflow_audit(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:10]:
    print(finding.format())
