"""Example: scan for insecure file/storage configuration in settings files."""

from devai import InsecureStorageSettingsAnalyzer

if __name__ == "__main__":
    analyzer = InsecureStorageSettingsAnalyzer(".")
    for finding in analyzer.analyze():
        print(finding.format())
    print(analyzer.summary())
