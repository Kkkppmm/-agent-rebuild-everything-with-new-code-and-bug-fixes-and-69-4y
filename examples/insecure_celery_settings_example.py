"""Example: scan for insecure Celery task queue configuration."""

from devai import InsecureCelerySettingsAnalyzer, SecurityScanner

# Standalone analyzer
analyzer = InsecureCelerySettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())

# Integrated security scan
report = SecurityScanner(".", checks=("insecure_celery_settings",)).scan()
print(report.summary())
