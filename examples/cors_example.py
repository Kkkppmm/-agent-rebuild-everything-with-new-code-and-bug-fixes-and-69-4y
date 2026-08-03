"""Example: scan for permissive CORS configurations."""

from devai import CORSAnalyzer

analyzer = CORSAnalyzer(".")
findings = analyzer.analyze()
print(analyzer.summary())
for finding in findings[:10]:
    print(finding.format())
