"""Scan project settings for insecure logging configuration."""

from devai import InsecureLoggingSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureLoggingSettingsAnalyzer(".")
    print(analyzer.summary())
    for finding in analyzer.analyze():
        print(finding.format())
