"""Example: scan for insecure database configuration."""

from devai import InsecureDatabaseSettingsAnalyzer, SecurityScanner

# Standalone analyzer
analyzer = InsecureDatabaseSettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())

# Or via unified security scan
report = SecurityScanner(".", checks=("insecure_database_settings",)).scan()
print(report.summary())
