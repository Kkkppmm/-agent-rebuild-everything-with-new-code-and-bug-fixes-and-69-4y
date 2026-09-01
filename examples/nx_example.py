"""Example: audit nx.json and project.json with NxAnalyzer."""

from devai.nx_analyzer import NxAnalyzer

analyzer = NxAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
