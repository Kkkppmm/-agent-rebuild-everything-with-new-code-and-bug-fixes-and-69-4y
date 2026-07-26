"""Basic DevAI usage example."""

from devai import DevAIConfig, MockLLMClient, SimpleChain
from devai.prompts import CODE_REVIEW
from devai.pipeline import DevPipeline

SAMPLE_CODE = '''
def fibonacci(n: int) -> int:
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)
'''


def main() -> None:
    client = MockLLMClient(responses=["This is a recursive fibonacci implementation."])

    # Simple chain
    chain = SimpleChain(client=client, prompt=CODE_REVIEW)
    result = chain.run(language="python", code=SAMPLE_CODE)
    print("Code Review:", result)

    # Pipeline
    pipeline = DevPipeline(client=client, language="python")
    explanation = pipeline.explain(SAMPLE_CODE)
    print("\nExplanation:", explanation)


if __name__ == "__main__":
    main()
