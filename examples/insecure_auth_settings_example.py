"""Example: scan Django auth settings for insecure configuration."""

from devai import InsecureAuthSettingsAnalyzer, SecurityScanner

# Scan a project directory for insecure auth settings
analyzer = InsecureAuthSettingsAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
for finding in findings:
    print(finding.format())

# Or run as part of the unified security scan
report = SecurityScanner(".", checks=("insecure_auth_settings",)).scan()
print(f"\nOverall score: {report.overall_score}/100")
