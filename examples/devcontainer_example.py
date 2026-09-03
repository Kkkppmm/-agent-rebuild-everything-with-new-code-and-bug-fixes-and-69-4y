"""DevContainerAnalyzer example — audit dev container configs for security issues."""

from devai import DevAI

dev = DevAI.mock()
analyzer = dev.devcontainer(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
print()
print("--- Hardened template ---")
print(analyzer.generate_hardened_template())
