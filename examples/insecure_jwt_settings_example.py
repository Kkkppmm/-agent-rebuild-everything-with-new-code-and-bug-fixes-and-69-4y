"""Example: scan for insecure JWT configuration."""

from devai import InsecureJwtSettingsAnalyzer, SecurityScanner

# Standalone analyzer
analyzer = InsecureJwtSettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())

# Integrated security scan
report = SecurityScanner(".", checks=("insecure_jwt_settings",)).scan()
print(report.summary())
