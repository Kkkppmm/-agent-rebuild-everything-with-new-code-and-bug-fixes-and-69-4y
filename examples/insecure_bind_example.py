"""Example: scan for services bound to all network interfaces."""

from devai import InsecureBindAnalyzer, SecurityScanner

if __name__ == "__main__":
    analyzer = InsecureBindAnalyzer(".")
    for finding in analyzer.analyze():
        print(finding.format())

    report = SecurityScanner(".", checks=("insecure_bind",)).scan()
    print(report.summary())
