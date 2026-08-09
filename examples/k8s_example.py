"""Audit Kubernetes manifests for security and best practices."""

from devai import DevAI

ai = DevAI()
analyzer = ai.k8s(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
