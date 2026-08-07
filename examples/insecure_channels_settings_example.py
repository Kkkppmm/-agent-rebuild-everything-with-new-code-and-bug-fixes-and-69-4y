"""Example: scan Django Channels settings for insecure configuration."""

from devai import InsecureChannelsSettingsAnalyzer, SecurityScanner

analyzer = InsecureChannelsSettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())

report = SecurityScanner(".", checks=("insecure_channels_settings",)).scan()
print(report.summary())
