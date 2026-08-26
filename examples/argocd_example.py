"""Audit Argo CD Application manifests for security and GitOps best practices."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.argocd(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
print()
print("Hardened template:")
print(analyzer.generate_hardened_template())
