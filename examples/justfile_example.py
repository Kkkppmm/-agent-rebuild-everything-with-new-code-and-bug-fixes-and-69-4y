"""Example: audit justfile with JustfileAnalyzer."""

from devai.justfile_analyzer import JustfileAnalyzer

analyzer = JustfileAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
