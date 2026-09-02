"""Example: audit Astral ty type checker configs with TyAnalyzer."""

from devai.ty_analyzer import TyAnalyzer

analyzer = TyAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings:
    print(finding.format())

if not findings:
    print("\nNo issues found. Hardened template:\n")
    print(analyzer.generate_hardened_template())
