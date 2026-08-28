"""Example: scan for insecure HTTPS transport security settings."""

from devai import InsecureTransportSettingsAnalyzer, SecurityScanner

# Standalone analyzer
analyzer = InsecureTransportSettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())

# Or via unified security scan
report = SecurityScanner(".", checks=("insecure_transport_settings",)).scan()
print(report.summary())
