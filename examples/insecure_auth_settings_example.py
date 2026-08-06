"""Example: scan for insecure authentication settings."""

from devai import InsecureAuthSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureAuthSettingsAnalyzer(".")
    for finding in analyzer.analyze():
        print(finding.format())
    print(analyzer.summary())
