"""Coder agent example with built-in tools."""

from devai import MockLLMClient
from devai.agents import CoderAgent

SAMPLE_CODE = '''
def divide(a, b):
    return a / b
'''


def main() -> None:
    client = MockLLMClient(
        responses=[
            "I'll analyze the code using the available tools.",
            "The function lacks error handling for division by zero.",
        ]
    )
    agent = CoderAgent(client=client)
    result = agent.review(SAMPLE_CODE)
    print("Agent Review:", result)


if __name__ == "__main__":
    main()
