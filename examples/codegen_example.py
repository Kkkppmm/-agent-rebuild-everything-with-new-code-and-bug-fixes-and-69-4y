"""Example: generate code from a specification using DevAI."""

from devai import CodeAssistant
from devai.core import MockLLMClient

client = MockLLMClient(
    default_response=(
        "def get_user_profile(user_id: int) -> dict:\n"
        '    """Fetch user profile by ID."""\n'
        "    if user_id <= 0:\n"
        '        raise ValueError("user_id must be positive")\n'
        "    return {'id': user_id, 'name': 'Alice'}"
    )
)
assistant = CodeAssistant(client=client)

spec = "REST endpoint helper that returns a user profile by ID with validation"
code = assistant.generate(spec, language="python")
print(code)

# Structured review with Pydantic output
review_client = MockLLMClient(
    default_response=(
        '{"summary": "Clean helper function", "score": 8, '
        '"issues": [{"severity": "low", "line": null, '
        '"message": "Consider adding async support", "suggestion": "Use async def"}]}'
    )
)
review_assistant = CodeAssistant(client=review_client)
result = review_assistant.structured_review(code)
print(f"\nScore: {result.score}/10")
print(f"Summary: {result.summary}")
for issue in result.issues:
    print(f"  [{issue.severity}] {issue.message}")
