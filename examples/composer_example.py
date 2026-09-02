"""Example: ProgramComposer and schedule config for automated workflows."""

import json
from datetime import datetime
from pathlib import Path

from devai import DevRuntime
from devai.library import ProgramLibrary


def main() -> None:
    runtime = DevRuntime.create(use_mock=True)

    # Build a program fluently in Python
    program = (
        runtime.composer("pre-push")
        .review("lint-check")
        .security("security-scan")
        .tests("test-coverage")
        .build()
    )
    results = program.run({"code": "def add(a, b): return a + b"})
    print(f"Pre-push program: {len(results)} steps completed")

    # Save and reload via program library
    programs_dir = Path("examples/programs")
    if programs_dir.is_dir():
        library = ProgramLibrary(programs_dir, runtime.assistant)
        entries = library.list()
        print(f"Program library: {len(entries)} programs")
        if entries:
            name = entries[0].name
            out = library.run(name, {"code": "def foo(): pass"})
            print(f"Ran '{name}': {len(out)} steps")

    # Schedule config (write a temp example)
    schedule_config = {
        "jobs": [
            {"name": "hourly-health", "cron": "0 * * * *", "program": "pre-commit"},
        ]
    }
    tmp = Path("/tmp/devai-schedule-example.json")
    tmp.write_text(json.dumps(schedule_config), encoding="utf-8")
    schedule = runtime.schedule()
    from devai.schedule_config import apply_schedule_config

    apply_schedule_config(schedule, schedule_config)
    due = schedule.run_due(dt=datetime(2026, 7, 29, 14, 0))
    print(f"Scheduled jobs at 14:00: {[r.job_name for r in due]}")


if __name__ == "__main__":
    main()
