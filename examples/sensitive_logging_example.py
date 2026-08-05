"""Example: scan for sensitive values logged to stdout or log files."""

from devai import SensitiveLoggingAnalyzer, SecurityScanner

if __name__ == "__main__":
    analyzer = SensitiveLoggingAnalyzer(".")
    print(analyzer.summary())
    for finding in analyzer.analyze()[:5]:
        print(finding.format())

    report = SecurityScanner(".", checks=("sensitive_logging",)).scan()
    print(f"\nSecurity scan score: {report.overall_score}/100")
