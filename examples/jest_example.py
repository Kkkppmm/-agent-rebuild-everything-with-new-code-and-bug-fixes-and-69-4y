"""Example: audit Jest test configuration with JestAnalyzer."""

from devai.jest_analyzer import JestAnalyzer

analyzer = JestAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings:
    print(finding.format())

if not findings:
    print("No issues found — or no Jest configs detected.")
    print("\nHardened config scaffold:")
    print(analyzer.generate_hardened_config())
