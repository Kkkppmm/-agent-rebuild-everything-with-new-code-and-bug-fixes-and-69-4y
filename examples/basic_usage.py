"""Basic usage example for DevAI."""

from devai import CodeAssistant
from devai.core import MockLLMClient

# Use mock client for demonstration (no API key needed)
client = MockLLMClient(
    default_response="This function correctly adds two numbers. Consider adding type hints."
)
assistant = CodeAssistant(client=client)

code = """
def add(a, b):
    return a + b
"""

print("=== Code Review ===")
print(assistant.review(code))

print("\n=== Explain ===")
print(assistant.explain(code))

print("\n=== Security Review ===")
print(assistant.security(code))

print("\n=== Full Review ===")
results = assistant.full_review(code)
for key, value in results.items():
    print(f"\n--- {key} ---")
    print(value)
