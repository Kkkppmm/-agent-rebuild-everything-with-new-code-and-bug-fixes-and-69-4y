"""Audit Kubernetes manifests with DevAI K8sManifestAnalyzer."""

from devai import K8sManifestAnalyzer

analyzer = K8sManifestAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
