"""Example: audit Kyverno Kubernetes policy manifests with DevAI."""

from devai import DevAI, KyvernoAnalyzer

# Direct analyzer usage
analyzer = KyvernoAnalyzer(".")
print(analyzer.summary())

for finding in analyzer.analyze():
    print(finding.format())

print(analyzer.to_context())

# Via DevAI facade
devai = DevAI.mock()
kyverno = devai.kyverno(".")
print(f"Health score: {kyverno.health_score()}/100")

# Generate a hardened policy template
print(kyverno.generate_hardened_template())
