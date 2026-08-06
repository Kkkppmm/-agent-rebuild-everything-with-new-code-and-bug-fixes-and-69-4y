"""Scan a project for insecure CORS configuration."""

from devai import InsecureCorsSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureCorsSettingsAnalyzer(".")
    print(analyzer.summary())
    for finding in analyzer.analyze():
        print(finding.format())
