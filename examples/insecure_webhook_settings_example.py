"""Example: scan for insecure webhook configuration."""

from devai import InsecureWebhookSettingsAnalyzer, SecurityScanner

analyzer = InsecureWebhookSettingsAnalyzer(".")
findings = analyzer.analyze()
print(analyzer.summary())
for finding in findings:
    print(finding.format())

report = SecurityScanner(".", checks=("insecure_webhook_settings",)).scan()
print(f"\nOverall score: {report.overall_score}")
