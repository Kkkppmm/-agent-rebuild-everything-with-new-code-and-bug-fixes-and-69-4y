"""DevTools example — static project analysis for developers."""

from pathlib import Path

from devai import DevRuntime, DevTools, ProgramComposer


def main() -> None:
    project = Path(__file__).parent.parent
    print(f"Analyzing project: {project}")

    # Static analysis with DevTools
    tools = DevTools(project)
    report = tools.full_report()
    print(f"Issues found: {report.issues_count()}")
    print(f"  Import modules: {report.imports.get('modules', 0)}")
    print(f"  Circular imports: {report.imports.get('circular_imports', 0)}")
    print(f"  Secrets: {report.secrets.get('total', 0)}")
    print(f"  Typing coverage: {report.typing.get('overall_coverage', 0):.1%}")
    print(f"  Docstring coverage: {report.docstrings.get('overall_coverage', 0):.1%}")
    print(f"  Dependencies: {report.dependencies.get('total', 0)}")

    # Build a program with ProgramComposer
    runtime = DevRuntime.create(use_mock=True, project_path=project)
    program = (
        runtime.composer("project-audit")
        .step("review", "review", input_key="code")
        .step("security", "security_audit", input_key="code")
        .describe("Full project audit")
        .tag("audit", "security")
        .build()
    )
    results = program.run({"code": "def add(a, b): return a + b"})
    print(f"\nProgram '{program.name}' completed {len(results)} steps")

    # Individual analyzers
    cycles = tools.import_graph().find_cycles()
    if cycles:
        print(f"\nCircular imports detected: {len(cycles)}")
        for c in cycles[:3]:
            print(f"  {c}")


if __name__ == "__main__":
    main()
