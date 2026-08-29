"""Audit TeamCity Kotlin DSL configs for security issues."""

from devai import DevAI

analyzer = DevAI.mock().teamcity(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:10]:
    print(finding.format())
