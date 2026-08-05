"""Example: scan for HTTP/socket/subprocess calls missing timeouts."""

from devai import MissingTimeoutAnalyzer, SecurityScanner

if __name__ == "__main__":
    analyzer = MissingTimeoutAnalyzer(".")
    for finding in analyzer.analyze():
        print(finding.format())

    report = SecurityScanner(".", checks=("missing_timeout",)).scan()
    print(report.summary())
