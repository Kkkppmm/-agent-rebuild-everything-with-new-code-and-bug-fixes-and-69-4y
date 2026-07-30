"""Example: orchestrate multiple DevAI presets with DevWorkflow."""

from devai import DevRuntime, DevWorkflow


def main() -> None:
    runtime = DevRuntime.create(use_mock=True)

    # Sequential workflow: pre-commit then docs generation
    workflow = (
        runtime.workflow("ship-it")
        .add("quality", "pre-commit")
        .add("docs", "docs-gen")
    )

    result = workflow.run(
        {
            "code": "def add(a, b):\n    return a + b\n",
            "project": "mylib",
            "description": "A tiny math library",
        }
    )

    print(result.summarize())
    print(f"\nCompleted in {result.duration_seconds:.2f}s")

    # Parallel workflow: run independent checks concurrently
    parallel = (
        DevWorkflow("parallel-gate", runtime.assistant)
        .add_parallel(
            "gate",
            ("review", "pre-commit"),
            ("hotfix", "hotfix"),
        )
    )
    parallel_result = parallel.run({"code": "def multiply(a, b): return a * b"})
    print(f"\nParallel steps: {len(parallel_result.steps)}")


if __name__ == "__main__":
    main()
