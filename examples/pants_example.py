"""Example: audit Pants BUILD files and pants.toml with PantsAnalyzer."""

from devai.pants_analyzer import PantsAnalyzer

analyzer = PantsAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("\nNo Pants configs found. Scaffold a hardened config:")
    print(analyzer.generate_hardened_config())
