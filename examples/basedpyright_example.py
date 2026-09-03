"""Example: audit Basedpyright configuration with BasedpyrightAnalyzer."""

from devai.basedpyright_analyzer import BasedpyrightAnalyzer

analyzer = BasedpyrightAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings:
    print(finding.format())
