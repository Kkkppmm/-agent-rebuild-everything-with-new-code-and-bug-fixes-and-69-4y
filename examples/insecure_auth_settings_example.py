"""Example: detect insecure authentication settings."""

from devai import InsecureAuthSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureAuthSettingsAnalyzer(".")
    findings = analyzer.analyze()
    print(analyzer.summary())
    for finding in findings[:10]:
        print(finding.format())
