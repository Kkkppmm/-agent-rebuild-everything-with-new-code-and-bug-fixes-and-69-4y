"""Scan a project for insecure cache configuration."""

from devai import InsecureCacheSettingsAnalyzer

analyzer = InsecureCacheSettingsAnalyzer(".")
findings = analyzer.analyze()
print(analyzer.summary())
for finding in findings[:10]:
    print(finding.format())
