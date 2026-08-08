"""Example: audit Makefiles with DevAI."""

from devai import MakefileAnalyzer

analyzer = MakefileAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
