"""Code sandbox example — run and verify generated Python code."""

from devai import CodeAssistant, MockLLMClient
from devai.sandbox import CodeSandbox

# Sandbox runs code in an isolated subprocess
sandbox = CodeSandbox()
result = sandbox.run_python("print(sum([1, 2, 3]))")
print("stdout:", result.stdout.strip())
print("success:", result.success)

# Generate code and verify with tests (uses mock LLM here)
assistant = CodeAssistant(client=MockLLMClient(default_response="def add(a, b):\n    return a + b"))
verified = assistant.generate_and_verify(
    "function that adds two numbers",
    "assert add(2, 3) == 5",
)
print("generated:", verified["code"])
print("verified:", verified["success"])
