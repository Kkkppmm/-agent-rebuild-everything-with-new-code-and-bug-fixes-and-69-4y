"""Example: scan for insecure webhook configuration."""

from devai import InsecureWebhookSettingsAnalyzer, SecurityScanner

# Standalone analyzer
analyzer = InsecureWebhookSettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())

# Integrated security scan
report = SecurityScanner(".", checks=("insecure_webhook_settings",)).scan()
print(report.summary())
