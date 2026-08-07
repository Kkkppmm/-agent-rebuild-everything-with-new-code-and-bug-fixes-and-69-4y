"""Example: scan Django middleware configuration for security issues."""

from devai import InsecureMiddlewareSettingsAnalyzer, SecurityScanner

# Standalone analyzer
analyzer = InsecureMiddlewareSettingsAnalyzer(".")
findings = analyzer.analyze()
print(analyzer.summary())
for finding in findings[:10]:
    print(finding.format())

# Integrated security scan
report = SecurityScanner(".", checks=("insecure_middleware_settings",)).scan()
print(report.summary())
