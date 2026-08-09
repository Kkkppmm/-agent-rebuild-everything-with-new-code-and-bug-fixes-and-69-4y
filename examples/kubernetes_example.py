"""Kubernetes manifest audit example."""

from devai import KubernetesAnalyzer

analyzer = KubernetesAnalyzer(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze()[:10]:
    print(finding.format())

print("\n--- LLM context ---")
print(analyzer.to_context()[:500], "...")
