"""Example: scan for insecure logging settings."""

from devai import InsecureLoggingSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureLoggingSettingsAnalyzer(".")
    for finding in analyzer.analyze():
        print(finding.format())
    print(analyzer.summary())
