"""Example: scan for insecure file and object storage settings."""

from devai import InsecureStorageSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureStorageSettingsAnalyzer(".")
    print(analyzer.summary())
    for finding in analyzer.analyze():
        print(finding.format())
