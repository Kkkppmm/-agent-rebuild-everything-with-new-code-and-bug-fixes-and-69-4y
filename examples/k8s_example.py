"""Example: audit Kubernetes manifests with DevAI K8sAnalyzer."""

from devai import K8sAnalyzer

analyzer = K8sAnalyzer(".")
print(analyzer.summary())

for finding in analyzer.analyze():
    print(finding.format())
