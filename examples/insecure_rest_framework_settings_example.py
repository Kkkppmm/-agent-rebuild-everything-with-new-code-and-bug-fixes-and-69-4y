"""Scan Django REST Framework settings for insecure defaults."""

from devai import InsecureRestFrameworkSettingsAnalyzer, SecurityScanner

# Standalone analyzer
analyzer = InsecureRestFrameworkSettingsAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())

# Integrated security scan
report = SecurityScanner(".", checks=("insecure_rest_framework_settings",)).scan()
print(f"\nOverall score: {report.overall_score}/100")
