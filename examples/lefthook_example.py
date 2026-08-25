"""Example: audit Lefthook git hook configs with LefthookAnalyzer."""

from devai.lefthook_analyzer import LefthookAnalyzer

analyzer = LefthookAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"Health score: {analyzer.health_score()}/100")
