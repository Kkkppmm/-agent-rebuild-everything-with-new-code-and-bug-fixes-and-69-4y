"""Example: DevAI doctor and report utilities."""

from devai import DevRuntime, run_doctor
from devai.report import ProgramReport


def main() -> None:
    print("=== DevAI Doctor ===")
    result = run_doctor(check_provider=True)
    print(result.summary())
    print()

    print("=== Program Report ===")
    runtime = DevRuntime.create(use_mock=True)
    results = runtime.run("pre-commit", {"code": "def add(a, b):\n    return a + b"})
    report = runtime.report(results, title="Pre-commit Report", preset="pre-commit")
    print(report.to_markdown())


if __name__ == "__main__":
    main()
