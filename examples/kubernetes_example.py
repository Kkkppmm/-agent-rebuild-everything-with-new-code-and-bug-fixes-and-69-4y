"""Audit Kubernetes manifests for pod security issues."""

from devai import DevAI

ai = DevAI()
analyzer = ai.kubernetes(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:10]:
    print(finding.format())
