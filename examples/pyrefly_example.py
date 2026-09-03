"""Example: audit Meta Pyrefly type checker configuration with PyreflyAnalyzer."""

from devai.pyrefly_analyzer import PyreflyAnalyzer

analyzer = PyreflyAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings:
    print(finding.format())
