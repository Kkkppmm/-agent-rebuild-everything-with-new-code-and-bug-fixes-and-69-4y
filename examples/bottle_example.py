"""Example: audit a Bottle project with DevAI."""

from devai import BottleAnalyzer

analyzer = BottleAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

if findings:
    print("\nTop findings:")
    for finding in findings[:10]:
        print(finding.format())
