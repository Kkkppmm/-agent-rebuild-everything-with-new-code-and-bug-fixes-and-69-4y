"""Examples for config, benchmark, git context, and tracing."""

from devai import DevRuntime, check_health, run_doctor
from devai.benchmark import benchmark_mock
from devai.config_file import config_file_template
from devai.git_context import GitContext
from devai.interpolate import interpolate
from devai.quickstart import quickstart
from devai.trace import DevTrace


def main() -> None:
    print("=== Health Check ===")
    print(check_health(use_mock=True).format_report())

    print("\n=== Doctor ===")
    print(run_doctor().format_report())

    print("\n=== Config Template ===")
    print(config_file_template().splitlines()[0])

    print("\n=== Interpolation ===")
    print(interpolate("Review ${var:file}", {"file": "main.py"}))

    print("\n=== Quickstart ===")
    runtime = quickstart(use_mock=True)
    print(runtime.review("def add(a, b): return a + b")[:80] + "...")

    print("\n=== Git Context ===")
    git = GitContext(".")
    if git.is_repo():
        print(f"Branch: {git.branch()}, Commit: {git.commit()}")

    print("\n=== Trace ===")
    trace = DevTrace("example")
    with trace.span("benchmark"):
        result = benchmark_mock(requests=2)
    print(trace.to_markdown())
    print(result.summarize())


if __name__ == "__main__":
    main()
