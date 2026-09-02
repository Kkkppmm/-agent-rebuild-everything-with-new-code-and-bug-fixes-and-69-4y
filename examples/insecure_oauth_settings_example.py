"""Example: scan for insecure OAuth2/OIDC configuration."""

from devai import InsecureOAuthSettingsAnalyzer, SecurityScanner

scanner = SecurityScanner(".", checks=("insecure_oauth_settings",))
report = scanner.scan()
print(report.summary())

analyzer = InsecureOAuthSettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())
