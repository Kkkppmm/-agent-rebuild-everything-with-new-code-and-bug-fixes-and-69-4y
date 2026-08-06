"""Example: scan for insecure storage configuration."""

from devai import InsecureStorageSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureStorageSettingsAnalyzer(".")
    print(analyzer.summary())
    for finding in analyzer.analyze():
        print(finding.format())
