"""Example: detect open redirect vulnerabilities in web handlers."""

from devai import DevAI

ai = DevAI()

# Analyze a project for open redirect risks
analyzer = ai.open_redirect(".")
findings = analyzer.analyze()

print(analyzer.summary())
if findings:
    print("\nSample findings:")
    for finding in findings[:5]:
        print(f"  {finding.format()}")

# Or run the full security scan (includes open redirect check)
report = ai.security_scan(".").scan()
print(f"\nOverall security score: {report.overall_score}/100")
