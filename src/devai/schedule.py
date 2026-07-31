"""DevSchedule — cron-like scheduling for DevAI programs and workflows."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from devai.program import DevProgram, ProgramResult
from devai.workflow import DevWorkflow, WorkflowResult

if TYPE_CHECKING:
    from devai.runtime import DevRuntime


CronCallback = Callable[[Any], None]


def _parse_field(field: str, min_val: int, max_val: int) -> set[int]:
    """Parse a single cron field into a set of matching values."""
    if field == "*":
        return set(range(min_val, max_val + 1))

    values: set[int] = set()
    for part in field.split(","):
        if "/" in part:
            base, step_str = part.split("/", 1)
            step = int(step_str)
            if base == "*":
                start, end = min_val, max_val
            elif "-" in base:
                start_str, end_str = base.split("-", 1)
                start, end = int(start_str), int(end_str)
            else:
                start, end = int(base), max_val
            values.update(range(start, end + 1, step))
        elif "-" in part:
            start_str, end_str = part.split("-", 1)
            values.update(range(int(start_str), int(end_str) + 1))
        else:
            values.add(int(part))
    return values


def cron_matches(expr: str, dt: datetime | None = None) -> bool:
    """Return True if a 5-field cron expression matches the given datetime.

    Supports ``*``, ranges (``1-5``), steps (``*/15``), and lists (``1,3,5``).
    Fields: minute hour day month weekday (weekday 0=Monday).
    """
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"Cron expression must have 5 fields, got {len(parts)}: {expr!r}")

    now = dt or datetime.now()
    minute, hour, day, month, weekday = parts
    if now.minute not in _parse_field(minute, 0, 59):
        return False
    if now.hour not in _parse_field(hour, 0, 23):
        return False
    if now.day not in _parse_field(day, 1, 31):
        return False
    if now.month not in _parse_field(month, 1, 12):
        return False
    # Python weekday: Monday=0; cron convention varies but we use Monday=0
    if now.weekday() not in _parse_field(weekday, 0, 6):
        return False
    return True


def validate_cron(expr: str) -> bool:
    """Validate a cron expression without evaluating it."""
    parts = expr.strip().split()
    if len(parts) != 5:
        return False
    try:
        minute, hour, day, month, weekday = parts
        _parse_field(minute, 0, 59)
        _parse_field(hour, 0, 23)
        _parse_field(day, 1, 31)
        _parse_field(month, 1, 12)
        _parse_field(weekday, 0, 6)
        return True
    except (ValueError, TypeError):
        return False


@dataclass
class ScheduledJob:
    """A scheduled program or workflow job."""

    name: str
    cron: str
    target: DevProgram | DevWorkflow | str
    context: dict[str, str] = field(default_factory=dict)
    last_run: datetime | None = None
    run_count: int = 0


@dataclass
class ScheduleResult:
    """Result from a single scheduled job execution."""

    job_name: str
    cron: str
    started_at: datetime
    duration_seconds: float
    results: list[ProgramResult] | WorkflowResult | None = None
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None


@dataclass
class DevSchedule:
    """Schedule DevAI programs and workflows on cron expressions.

    DevSchedule polls cron expressions and runs jobs when they match the
    current time. Use it to automate nightly audits, hourly health checks,
    or any recurring developer workflow.
    """

    runtime: "DevRuntime"
    jobs: list[ScheduledJob] = field(default_factory=list)
    _callbacks: list[CronCallback] = field(default_factory=list, init=False, repr=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _history: list[ScheduleResult] = field(default_factory=list, init=False, repr=False)

    def add(
        self,
        name: str,
        cron: str,
        target: DevProgram | DevWorkflow | str,
        *,
        context: dict[str, str] | None = None,
    ) -> DevSchedule:
        """Register a job with a cron expression."""
        if not validate_cron(cron):
            raise ValueError(f"Invalid cron expression: {cron!r}")
        self.jobs.append(
            ScheduledJob(
                name=name,
                cron=cron,
                target=target,
                context=context or {},
            )
        )
        return self

    def on_run(self, callback: CronCallback) -> DevSchedule:
        """Register a callback fired after each job run."""
        self._callbacks.append(callback)
        return self

    @property
    def history(self) -> list[ScheduleResult]:
        """Return execution history for all completed runs."""
        return list(self._history)

    def run_due(self, *, dt: datetime | None = None) -> list[ScheduleResult]:
        """Run all jobs whose cron expression matches the current minute."""
        now = dt or datetime.now()
        # Truncate to minute for deduplication
        current_minute = now.replace(second=0, microsecond=0)
        results: list[ScheduleResult] = []

        for job in self.jobs:
            if not cron_matches(job.cron, now):
                continue
            if job.last_run and job.last_run.replace(second=0, microsecond=0) == current_minute:
                continue

            result = self._execute_job(job, now)
            job.last_run = now
            job.run_count += 1
            results.append(result)
            self._history.append(result)
            for cb in self._callbacks:
                cb(result)

        return results

    def _execute_job(self, job: ScheduledJob, started_at: datetime) -> ScheduleResult:
        start = time.monotonic()
        try:
            if isinstance(job.target, DevWorkflow):
                output = self.runtime.run_workflow(job.target, job.context)
            else:
                output = self.runtime.run(job.target, job.context)
            return ScheduleResult(
                job_name=job.name,
                cron=job.cron,
                started_at=started_at,
                duration_seconds=time.monotonic() - start,
                results=output,
            )
        except Exception as e:
            return ScheduleResult(
                job_name=job.name,
                cron=job.cron,
                started_at=started_at,
                duration_seconds=time.monotonic() - start,
                error=str(e),
            )

    def start(self, *, poll_interval: float = 30.0) -> None:
        """Start background polling for due jobs."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()

        def _poll() -> None:
            while not self._stop_event.is_set():
                self.run_due()
                self._stop_event.wait(poll_interval)

        self._thread = threading.Thread(target=_poll, daemon=True, name="devai-schedule")
        self._thread.start()

    def stop(self, *, timeout: float = 5.0) -> None:
        """Stop background polling."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._thread = None

    def run_once(self, name: str, context: dict[str, str] | None = None) -> ScheduleResult:
        """Run a named job immediately, ignoring its cron schedule."""
        job = next((j for j in self.jobs if j.name == name), None)
        if job is None:
            raise ValueError(f"Unknown job: {name!r}")
        merged = {**job.context, **(context or {})}
        now = datetime.now()
        result = self._execute_job(
            ScheduledJob(
                name=job.name,
                cron=job.cron,
                target=job.target,
                context=merged,
            ),
            now,
        )
        job.run_count += 1
        self._history.append(result)
        return result
