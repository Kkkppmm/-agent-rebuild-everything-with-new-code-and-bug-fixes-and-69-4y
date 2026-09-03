"""Example: audit Astral ty type checker configuration with TyAnalyzer."""

from devai.ty_analyzer import TyAnalyzer

analyzer = TyAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings:
    print(finding.format())
