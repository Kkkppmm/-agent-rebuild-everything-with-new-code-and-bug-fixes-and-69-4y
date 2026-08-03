"""Example: scan for insecure JWT handling."""

from devai import JWTSecurityAnalyzer

analyzer = JWTSecurityAnalyzer(".")
findings = analyzer.analyze()
print(analyzer.summary())
for finding in findings[:10]:
    print(finding.format())
