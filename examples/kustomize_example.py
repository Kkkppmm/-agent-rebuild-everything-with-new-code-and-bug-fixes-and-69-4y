"""Example: audit Kustomize overlays with DevAI."""

from devai import DevAI

devai = DevAI.mock()
analyzer = devai.kustomize(".")

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

findings = analyzer.analyze()
for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("\nNo issues found. Hardened overlay template:\n")
    print(analyzer.generate_hardened_overlay())
