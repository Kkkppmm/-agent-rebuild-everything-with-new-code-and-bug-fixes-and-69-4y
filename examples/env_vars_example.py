"""Example: inventory environment variables and detect config drift."""

from devai import DevAI

ai = DevAI.mock()

# Analyze env var drift in the current project
analyzer = ai.env_vars(".")
print(analyzer.summary())

# Show gaps with details
for gap in analyzer.analyze():
    print(gap.format())

# Export LLM-ready context for onboarding docs
print(analyzer.to_context())

# Scaffold a .env.example from code references
print(analyzer.generate_example())
