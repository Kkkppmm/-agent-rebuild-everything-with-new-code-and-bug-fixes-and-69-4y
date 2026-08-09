"""Makefile audit example."""

from devai import MakefileAnalyzer

analyzer = MakefileAnalyzer(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze()[:10]:
    print(finding.format())
