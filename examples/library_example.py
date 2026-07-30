"""ProgramLibrary and export example."""

from pathlib import Path

from devai import CodeAssistant, DevProgram, ProgramLibrary, export_program_to_file, quickstart
from devai.core import MockLLMClient


def main() -> None:
    programs_dir = Path(__file__).parent / "programs"
    assistant = CodeAssistant(client=MockLLMClient(default_response="Looks good"))
    library = ProgramLibrary(programs_dir, assistant)

    print("=== Program Library ===")
    for entry in library.discover():
        print(f"- {entry.name}: {entry.description or entry.actions}")

    print("\n=== Search 'review' ===")
    for entry in library.search("review"):
        print(f"- {entry.name} ({entry.task_count} tasks)")

    print("\n=== Run pre-commit program ===")
    results = library.run("pre-commit", {"code": "def add(a, b): return a + b"})
    for result in results:
        print(f"{result.name}: {result.output[:60]}...")

    print("\n=== Export program to script ===")
    program = library.get("pre-commit")
    output = Path("exported_pre_commit.py")
    export_program_to_file(program, output, use_mock=True)
    print(f"Exported to {output.resolve()}")

    print("\n=== Quickstart runtime ===")
    runtime = quickstart(use_mock=True)
    print(runtime.review("def multiply(a, b): return a * b")[:80])


if __name__ == "__main__":
    main()
