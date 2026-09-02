"""Example: audit Conda environment and recipe files with CondaAnalyzer."""

from devai.conda_analyzer import CondaAnalyzer

analyzer = CondaAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
