"""Example: audit Go module configuration with GoModAnalyzer."""

from devai import GoModAnalyzer

analyzer = GoModAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

if findings:
    print("\nFindings:")
    for finding in findings[:10]:
        print(f"  {finding.format()}")
else:
    print("\nNo issues found.")

print("\nLLM context:")
print(analyzer.to_context())
