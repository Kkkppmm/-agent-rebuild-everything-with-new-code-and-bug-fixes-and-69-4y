"""Tests for DevSchedule."""

from datetime import datetime

import pytest

from devai import DevRuntime
from devai.schedule import DevSchedule, cron_matches, validate_cron


class TestCron:
    def test_validate_valid(self):
        assert validate_cron("0 * * * *")
        assert validate_cron("*/15 9-17 * * 1-5")

    def test_validate_invalid(self):
        assert not validate_cron("not a cron")
        assert not validate_cron("* * *")

    def test_cron_matches_wildcard(self):
        now = datetime(2026, 7, 29, 14, 30)
        assert cron_matches("* * * * *", now)

    def test_cron_matches_specific(self):
        now = datetime(2026, 7, 29, 14, 30)
        assert cron_matches(f"30 14 29 7 {now.weekday()}", now)
        assert not cron_matches("0 14 29 7 1", now)

    def test_cron_step(self):
        now = datetime(2026, 7, 29, 14, 15)
        assert cron_matches("*/15 * * * *", now)


class TestDevSchedule:
    def test_add_job(self):
        runtime = DevRuntime.create(use_mock=True)
        schedule = runtime.schedule()
        schedule.add("audit", "0 * * * *", "pre-commit")
        assert len(schedule.jobs) == 1

    def test_invalid_cron_raises(self):
        runtime = DevRuntime.create(use_mock=True)
        schedule = runtime.schedule()
        with pytest.raises(ValueError):
            schedule.add("bad", "invalid", "pre-commit")

    def test_run_once(self):
        runtime = DevRuntime.create(use_mock=True)
        schedule = runtime.schedule()
        schedule.add("audit", "0 0 1 1 0", "pre-commit")
        result = schedule.run_once("audit", {"code": "def foo(): pass"})
        assert result.success
        assert result.job_name == "audit"

    def test_run_due_skips_non_matching(self):
        runtime = DevRuntime.create(use_mock=True)
        schedule = runtime.schedule()
        schedule.add("never", "0 0 1 1 0", "pre-commit")
        results = schedule.run_due(dt=datetime(2026, 7, 29, 14, 30))
        assert results == []

    def test_run_due_executes_matching(self):
        runtime = DevRuntime.create(use_mock=True)
        schedule = runtime.schedule()
        schedule.add("hourly", "30 14 * * *", "pre-commit")
        dt = datetime(2026, 7, 29, 14, 30)
        results = schedule.run_due(dt=dt)
        assert len(results) == 1
        assert results[0].success

    def test_callback(self):
        runtime = DevRuntime.create(use_mock=True)
        schedule = runtime.schedule()
        schedule.add("job", "30 14 * * *", "pre-commit")
        fired: list[str] = []
        schedule.on_run(lambda r: fired.append(r.job_name))
        schedule.run_due(dt=datetime(2026, 7, 29, 14, 30))
        assert fired == ["job"]

    def test_resilient_client(self):
        runtime = DevRuntime.create(use_mock=True)
        client = runtime.resilient_client(requests_per_minute=6000)
        from devai.core import Message

        result = client.complete([Message.user("test")])
        assert isinstance(result, str)
