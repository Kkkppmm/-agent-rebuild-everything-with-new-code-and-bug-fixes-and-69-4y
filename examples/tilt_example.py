"""Example: audit Tiltfiles with DevAI."""

from devai import DevAI

devai = DevAI.mock()
analyzer = devai.tilt(".")

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

findings = analyzer.analyze()
for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("\nNo issues found. Hardened config template:\n")
    print(analyzer.generate_hardened_config())
