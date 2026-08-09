"""Example: audit Nginx configuration files with DevAI."""

from devai import NginxAnalyzer

analyzer = NginxAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:10]:
    print(finding.format())
