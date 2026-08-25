"""Example: audit justfile recipes with JustAnalyzer."""

from devai.just_analyzer import JustAnalyzer

analyzer = JustAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("No issues found — or no justfile present.")
    print("\nHardened template:\n")
    print(analyzer.generate_hardened_template())
