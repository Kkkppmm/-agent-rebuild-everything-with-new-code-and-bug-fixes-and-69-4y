"""Example: audit a NestJS application with DevAI."""

from devai import NestJSAnalyzer

analyzer = NestJSAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
