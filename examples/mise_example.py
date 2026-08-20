"""Example: audit mise/asdf runtime version configuration with DevAI."""

from devai import DevAI

dev = DevAI.mock()
analyzer = dev.mise(".")

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

findings = analyzer.analyze()
if findings:
    print("\nFindings:")
    for finding in findings[:10]:
        print(f"  {finding.format()}")
else:
    print("\nNo security issues found in mise configs.")

print("\n--- LLM context ---")
print(analyzer.to_context()[:500])
