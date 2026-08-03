"""Example: scan a project for NoSQL injection risks."""

from devai import NoSQLInjectionAnalyzer

analyzer = NoSQLInjectionAnalyzer(".")
findings = analyzer.analyze()
print(analyzer.summary())
for finding in findings[:10]:
    print(finding.format())
