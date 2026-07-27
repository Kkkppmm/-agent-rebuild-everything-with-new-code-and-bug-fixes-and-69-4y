"""Basic usage example for DevAI."""

from devai import CodeAssistant, MockLLMClient

code = '''
def divide(a, b):
  return a / b
'''

client = MockLLMClient()
assistant = CodeAssistant(client=client)

print("=== Code Review ===")
print(assistant.review(code))

print("\n=== Explanation ===")
print(assistant.explain(code))

print("\n=== Debug ===")
print(assistant.debug(code, error="ZeroDivisionError: division by zero"))
