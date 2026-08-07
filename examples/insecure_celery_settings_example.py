"""Scan for insecure Celery configuration."""

from devai import InsecureCelerySettingsAnalyzer, SecurityScanner

analyzer = InsecureCelerySettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())

print()
print(analyzer.summary())

report = SecurityScanner(".", checks=("insecure_celery_settings",)).scan()
print(f"\nSecurity scan score: {report.overall_score}/100")
