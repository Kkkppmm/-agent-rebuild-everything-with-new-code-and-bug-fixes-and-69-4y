"""Example: detect insecure session and CSRF cookie settings."""

from devai import InsecureSessionSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureSessionSettingsAnalyzer(".")
    findings = analyzer.analyze()
    print(analyzer.summary())
    for finding in findings[:10]:
        print(finding.format())
