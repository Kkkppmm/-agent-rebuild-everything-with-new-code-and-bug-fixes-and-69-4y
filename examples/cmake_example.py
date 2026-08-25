"""Example: audit CMake configuration with DevAI."""

from devai import DevAI

dev = DevAI.mock()
analyzer = dev.cmake(".")

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze()[:10]:
    print(finding.format())

print("\n--- Hardened config snippet ---")
print(analyzer.generate_hardened_config())
