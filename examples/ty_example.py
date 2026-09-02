"""TyAnalyzer example — audit Astral ty type checker configuration."""

from devai import TyAnalyzer

analyzer = TyAnalyzer(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

findings = analyzer.analyze()
if findings:
    print("\nFindings:")
    for finding in findings[:10]:
        print(f"  {finding.format()}")

print("\n=== LLM context ===")
print(analyzer.to_context())

print("\n=== Hardened template ===")
print(analyzer.generate_hardened_template())
