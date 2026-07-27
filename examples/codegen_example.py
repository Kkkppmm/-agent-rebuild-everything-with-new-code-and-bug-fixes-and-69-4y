"""Example: code generation and structured review with DevAI."""

from devai import CodeAssistant, CodeReviewResult
from devai.core import MockLLMClient

# Mock client for demo (use DevAIConfig with a real API key in production)
client = MockLLMClient(
    default_response=(
        '{"summary": "Clean implementation", "score": 8, '
        '"issues": [{"severity": "low", "message": "Add type hints", "suggestion": "Use int"}]}'
    )
)
assistant = CodeAssistant(client=client)

# Generate code from a specification
spec = "A Python function that validates email addresses using regex"
generated = assistant.generate(spec, language="python")
print("Generated:", generated)

# Structured review returns a Pydantic model
code = "def add(a, b):\n    return a + b"
review: CodeReviewResult = assistant.structured_review(code)
print(f"Score: {review.score}/10 — {review.summary}")
for issue in review.issues:
    print(f"  [{issue.severity}] {issue.message}")
