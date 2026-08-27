"""VagrantAnalyzer example — audit Vagrantfiles for security issues."""

from devai import DevAI

dev = DevAI.mock()
analyzer = dev.vagrant(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
print()
print("--- Hardened template ---")
print(analyzer.generate_hardened_template())
