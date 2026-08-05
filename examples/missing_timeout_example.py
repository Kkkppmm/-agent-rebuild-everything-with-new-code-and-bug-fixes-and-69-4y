"""Example: detect HTTP and subprocess calls missing timeouts."""

from devai import MissingTimeoutAnalyzer

if __name__ == "__main__":
    analyzer = MissingTimeoutAnalyzer(".")
    findings = analyzer.analyze()
    print(analyzer.summary())
    for finding in findings[:10]:
        print(finding.format())
