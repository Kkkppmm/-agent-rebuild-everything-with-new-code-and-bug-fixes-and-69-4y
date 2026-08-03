"""Example: scan a project for insecure cookie configurations."""

from devai import InsecureCookieAnalyzer

analyzer = InsecureCookieAnalyzer(".")
findings = analyzer.analyze()
print(analyzer.summary())
for finding in findings[:10]:
    print(finding.format())
