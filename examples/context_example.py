"""DevContext and PromptBuilder example."""

from devai import DevContext, PromptBuilder, quickstart
from devai.core import MockLLMClient


def main() -> None:
    # Build context from code snippets and variables
    ctx = (
        DevContext()
        .snippet(
            "def divide(a, b):\n    return a / b",
            language="python",
            label="Target function",
        )
        .text("Focus on edge cases and error handling.", label="Instructions")
        .vars(severity="high")
    )

    print("=== Built context ===")
    print(ctx.build())
    print(f"\nEstimated tokens: {ctx.token_count()}")

    # Use PromptBuilder for structured messages
    messages = (
        PromptBuilder()
        .system("You are a senior Python code reviewer.")
        .context(ctx)
        .user("Review the code for bugs. Severity: ${var:severity}")
        .build()
    )

    print("\n=== Messages ===")
    for msg in messages:
        role = msg.role if isinstance(msg.role, str) else msg.role.value
        print(f"[{role}] {msg.content[:80]}...")

    # Send to LLM (mock mode — no API key needed)
    client = MockLLMClient()
    response = client.complete(messages)
    print(f"\n=== LLM response ===\n{response.content}")

    # Or use with DevRuntime
    runtime = quickstart(use_mock=True)
    review_ctx = DevContext().snippet("def add(a, b): return a + b", label="Code")
    result = runtime.assistant.review(review_ctx.build())
    print(f"\n=== Runtime review ===\n{result[:200]}...")


if __name__ == "__main__":
    main()
