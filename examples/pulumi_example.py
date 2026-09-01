"""Example: audit Pulumi IaC projects with PulumiAnalyzer."""

from devai import PulumiAnalyzer

if __name__ == "__main__":
    analyzer = PulumiAnalyzer(".")
    print(analyzer.summary())
    print(f"Health score: {analyzer.health_score()}/100")
    findings = analyzer.analyze()
    for finding in findings[:10]:
        print(finding.format())
    if len(findings) > 10:
        print(f"... and {len(findings) - 10} more finding(s)")
