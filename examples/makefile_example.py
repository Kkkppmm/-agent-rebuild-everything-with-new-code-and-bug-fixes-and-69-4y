"""Example: audit Makefiles for security risks and build best practices."""

from devai import MakefileAnalyzer

analyzer = MakefileAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

if findings:
    print("\nFindings:")
    for finding in findings[:10]:
        print(f"  {finding.format()}")
else:
    print("\nNo issues found.")

print("\n--- LLM context ---")
print(analyzer.to_context())
