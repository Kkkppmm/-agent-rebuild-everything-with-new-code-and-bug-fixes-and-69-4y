"""Scan a project for insecure email configuration."""

from devai import InsecureEmailSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureEmailSettingsAnalyzer(".")
    print(analyzer.summary())
    for finding in analyzer.analyze():
        print(finding.format())
