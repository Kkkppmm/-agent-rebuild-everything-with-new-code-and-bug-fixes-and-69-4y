"""Example: audit AWS CloudFormation templates with CloudFormationAnalyzer."""

from devai import CloudFormationAnalyzer

if __name__ == "__main__":
    analyzer = CloudFormationAnalyzer(".")
    print(analyzer.summary())
    print(f"Health score: {analyzer.health_score()}/100")
    findings = analyzer.analyze()
    for finding in findings[:10]:
        print(finding.format())
    if len(findings) > 10:
        print(f"... and {len(findings) - 10} more finding(s)")
