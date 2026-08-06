"""Example: scan for insecure logging configuration."""

from devai import InsecureLoggingSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureLoggingSettingsAnalyzer(".")
    for finding in analyzer.analyze():
        print(finding.format())
    print(analyzer.summary())
