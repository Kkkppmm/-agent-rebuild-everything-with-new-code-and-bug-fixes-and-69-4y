"""Example: DevSchedule for cron-like automation."""

from datetime import datetime

from devai import DevRuntime
from devai.schedule import cron_matches


def main() -> None:
    runtime = DevRuntime.create(use_mock=True)

    # Validate a cron expression
    expr = "0 * * * *"  # every hour at minute 0
    print(f"Cron {expr!r} valid and matches now: {cron_matches(expr)}")

    # Schedule nightly audit and code health checks
    schedule = runtime.schedule()
    schedule.add("nightly-audit", "0 2 * * *", "nightly-audit")
    schedule.add("hourly-health", "0 * * * *", "code-health")

    # Run a job immediately (ignoring cron)
    result = schedule.run_once(
        "hourly-health",
        context={"code": "def add(a, b):\n    return a + b\n"},
    )
    print(f"Job success: {result.success}, duration: {result.duration_seconds:.2f}s")
    if result.results:
        print(runtime.summarize(result.results))  # type: ignore[arg-type]

    # Run all jobs due at a specific time
    due = schedule.run_due(dt=datetime(2026, 7, 29, 2, 0))
    print(f"Due jobs at 02:00: {[r.job_name for r in due]}")

    # Resilient client with rate limiting, circuit breaker, and metrics
    client = runtime.resilient_client(requests_per_minute=120)
    from devai.core import Message

    response = client.complete([Message.user("Review this function")])
    print(f"Resilient client response length: {len(response)}")


if __name__ == "__main__":
    main()
