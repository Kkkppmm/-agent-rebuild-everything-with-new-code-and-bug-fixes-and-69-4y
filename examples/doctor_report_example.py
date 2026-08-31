"""DevAI doctor and report examples."""

from devai import DevDoctor, ProgramReport, quickstart


def main() -> None:
    # Environment diagnostics
    doctor = DevDoctor()
    print(doctor.summary())
    print()

    # Run a program and export results
    runtime = quickstart(use_mock=True)
    results = runtime.run("pre-commit", {"code": "def add(a, b): return a + b"})
    report = ProgramReport.from_program_results(
        results,
        title="Pre-commit Report",
        program_name="pre-commit",
    )
    print(report.to_markdown())
    print()
    print("JSON preview:", report.to_json()[:200], "...")


if __name__ == "__main__":
    main()
