"""Basic DevAI usage — no API key required (mock client)."""

from devai.core.client import MockLLMClient
from devai.pipeline import DevPipeline
from devai.prompts import PromptTemplate, CODE_REVIEW

CODE = '''
def divide(a, b):
    return a / b
'''

def main() -> None:
    client = MockLLMClient(responses=["Looks good, but add a zero-division check."])
    pipeline = DevPipeline(client=client)

    # Direct prompt
    prompt = PromptTemplate(CODE_REVIEW).format(code=CODE, language="python")
    print("=== Code Review ===")
    print(client.complete(prompt).content)

    # Pipeline API
    print("\n=== Pipeline Review ===")
    result = pipeline.review(CODE)
    print(result.response.content)

if __name__ == "__main__":
    main()
