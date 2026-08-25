"""Example: audit Justfile for security risks with DevAI."""

from devai import JustfileAnalyzer

analyzer = JustfileAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings:
    print(finding.format())

if not findings:
    print("\nHardened template:\n")
    print(analyzer.generate_hardened_config())
