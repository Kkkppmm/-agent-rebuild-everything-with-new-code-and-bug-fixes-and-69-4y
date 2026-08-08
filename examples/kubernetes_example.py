"""Example: audit Kubernetes manifests with DevAI."""

from devai import KubernetesAnalyzer

analyzer = KubernetesAnalyzer(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
