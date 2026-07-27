"""Basic DevAI usage examples."""

from devai import CodeAssistant, DevAIConfig

config = DevAIConfig.mock()
assistant = CodeAssistant(config=config)

code = '''
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
'''

print("=== Code Review ===")
print(assistant.review(code))

print("\n=== Explain ===")
print(assistant.explain(code))

print("\n=== Security Review ===")
print(assistant.security(code))

print("\n=== Generate Tests ===")
print(assistant.generate_tests(code))
