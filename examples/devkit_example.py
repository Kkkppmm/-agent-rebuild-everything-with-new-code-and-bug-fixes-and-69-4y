"""Example: DevKit unified developer workspace."""

from devai import DevKit, MockLLMClient

# Create a DevKit with a mock client (no API key needed)
kit = DevKit.from_client(MockLLMClient(default_response="Looks good."), project_path=".")

# List built-in program presets
print("Available presets:")
for preset in kit.presets():
    print(f"  - {preset['name']}: {preset['description']}")

# Run a pre-commit audit on a code snippet
code = """
def divide(a, b):
    return a / b
"""

print("\n--- Pre-commit audit ---")
print(kit.pre_commit(code))

# Run a full audit pipeline
print("\n--- Full audit ---")
print(kit.audit(code))

# Load and run a preset programmatically
program = kit.preset("onboarding")
results = kit.run_program(program, {"code": code})
print("\n--- Onboarding results ---")
print(kit.summarize(results))
