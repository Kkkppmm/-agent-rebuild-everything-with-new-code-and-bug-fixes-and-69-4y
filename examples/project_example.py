"""Example: index a project and review it with DevAI."""

from devai import CodeAssistant, CodeProject
from devai.core import MockLLMClient
from devai.rag import RAGChain


def main() -> None:
    project = CodeProject(".")
    print(project.summary())
    print(f"Estimated tokens: {project.token_estimate()}")

    store = project.to_vector_store()
    client = MockLLMClient(default_response="Based on the codebase, the auth module needs tests.")
    chain = RAGChain(client=client, store=store)
    answer = chain.query("Where is authentication handled?")
    print(f"\nRAG answer: {answer}")

    assistant = CodeAssistant(client=client)
    review = assistant.review_project(".", query="error handling")
    print(f"\nProject review: {review[:200]}...")


if __name__ == "__main__":
    main()
