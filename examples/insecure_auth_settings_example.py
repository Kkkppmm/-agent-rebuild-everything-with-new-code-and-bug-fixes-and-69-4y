"""Example: scan for insecure authentication settings."""

from devai import InsecureAuthSettingsAnalyzer, SecurityScanner

if __name__ == "__main__":
    analyzer = InsecureAuthSettingsAnalyzer(".")
    for finding in analyzer.analyze():
        print(finding.format())

    report = SecurityScanner(".", checks=("insecure_auth_settings",)).scan()
    print(report.summary())
