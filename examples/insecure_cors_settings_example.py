"""Example: scan for insecure CORS configuration in settings files."""

from devai import InsecureCorsSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureCorsSettingsAnalyzer(".")
    for finding in analyzer.analyze():
        print(finding.format())
    print(analyzer.summary())
