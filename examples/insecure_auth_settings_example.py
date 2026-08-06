"""Example: scan for insecure authentication settings."""

from devai import InsecureAuthSettingsAnalyzer, SecurityScanner

if __name__ == "__main__":
    root = "."
    analyzer = InsecureAuthSettingsAnalyzer(root)
    findings = analyzer.analyze()
    print(analyzer.summary())
    for finding in findings[:10]:
        print(finding.format())

    report = SecurityScanner(root, checks=("insecure_auth_settings",)).scan()
    print(f"\nSecurity scan score: {report.overall_score}/100")
