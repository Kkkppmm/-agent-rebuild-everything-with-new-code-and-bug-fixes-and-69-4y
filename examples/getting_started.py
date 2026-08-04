"""Getting started with DevAI — the Python AI library for developers and programs."""

from devai import DevRuntime, quickstart
from devai.core import MockLLMClient
from devai.presets import get_preset, list_presets


def demo_quickstart() -> None:
    """One-line setup with quickstart()."""
    ai = quickstart(use_mock=True)
    print("=== Quickstart Review ===")
    print(ai.review("def hello(): print('hi')"))


def demo_runtime_and_programs() -> None:
    """Bootstrap DevRuntime and run a built-in preset program."""
    runtime = DevRuntime.create(use_mock=True)
    print("\n=== Available Presets ===")
    print(", ".join(p["name"] for p in list_presets()))

    program = get_preset("pre-commit", assistant=runtime.assistant)
    code = "def add(a, b):\n    return a + b\n"
    print("\n=== Pre-commit Program ===")
    for result in program.run({"code": code}):
        print(f"  [{result.name}] {result.output[:80]}...")


def demo_mock_client() -> None:
    """Use MockLLMClient for tests and examples without API keys."""
    client = MockLLMClient(default_response="Looks good — add type hints.")
    from devai import CodeAssistant

    assistant = CodeAssistant(client=client)
    print("\n=== Mock Client Explain ===")
    print(assistant.explain("lambda x: x * 2"))


if __name__ == "__main__":
    demo_quickstart()
    demo_runtime_and_programs()
    demo_mock_client()
    print("\nDone! See README.md for full documentation.")
