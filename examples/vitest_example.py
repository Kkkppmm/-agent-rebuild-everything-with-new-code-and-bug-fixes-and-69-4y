"""Example: audit Vitest and Vite test configuration with VitestAnalyzer."""

from devai.vitest_analyzer import VitestAnalyzer

analyzer = VitestAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings:
    print(finding.format())

if not findings:
    print("\nNo issues found. Hardened config template:\n")
    print(analyzer.generate_hardened_config())
