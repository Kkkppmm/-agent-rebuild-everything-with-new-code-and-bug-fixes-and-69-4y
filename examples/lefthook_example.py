"""Example: audit lefthook git hook configs with LefthookAnalyzer."""

from devai.lefthook_analyzer import LefthookAnalyzer

analyzer = LefthookAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("No issues found — or no lefthook config present.")
    print("\nHardened template:\n")
    print(analyzer.generate_hardened_template())
