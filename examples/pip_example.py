"""Example: audit pip requirements.txt and pip.conf with PipAnalyzer."""

from devai.pip_analyzer import PipAnalyzer

analyzer = PipAnalyzer(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")
for finding in analyzer.analyze()[:10]:
    print(finding.format())
