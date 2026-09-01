"""Example: audit maturin Rust/Python extension projects with DevAI."""

from devai import MaturinAnalyzer

analyzer = MaturinAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("\nHardened config template:")
    print(analyzer.generate_hardened_config())
