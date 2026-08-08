"""Example: audit Kubernetes manifests with DevAI."""

from devai import KubernetesAnalyzer

analyzer = KubernetesAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
