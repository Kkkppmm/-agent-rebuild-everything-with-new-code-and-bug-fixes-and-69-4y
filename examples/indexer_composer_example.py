"""Example: CodeIndexer and ProgramComposer (DevAI v3.0)."""

from devai import CodeAssistant, CodeIndexer, CodeProject, ProgramComposer
from devai.core import MockLLMClient


def main() -> None:
    assistant = CodeAssistant(client=MockLLMClient())

    # Index symbols in the current project
    indexer = CodeIndexer(".")
    indexer.index_directory()
    print("Indexed symbols:", len(indexer.symbols))
    for symbol in indexer.search("review", limit=5):
        print(" ", symbol.display())

    project = CodeProject("src/devai")
    print(project.symbol_context("assistant", max_symbols=10))

    # Compose a custom program from presets
    composer = ProgramComposer.from_presets(assistant, ["pre-commit", "security-deep-dive"])
    composer.dedupe_actions()
    print(composer.describe())

    program = composer.build()
    results = program.run({"code": "def add(a, b): return a + b"})
    for result in results:
        print(f"{result.name}: {result.output[:80]}...")


if __name__ == "__main__":
    main()
