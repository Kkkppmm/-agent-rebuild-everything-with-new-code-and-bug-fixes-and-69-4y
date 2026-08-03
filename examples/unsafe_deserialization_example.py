"""Example: scan for unsafe deserialization patterns."""

from devai import UnsafeDeserializationAnalyzer

analyzer = UnsafeDeserializationAnalyzer(".")
findings = analyzer.analyze()
print(analyzer.summary())
for finding in findings[:10]:
    print(finding.format())
