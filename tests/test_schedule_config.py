"""Tests for schedule config loading."""

import json
from datetime import datetime

import pytest

from devai import DevRuntime
from devai.library import ProgramLibrary
from devai.schedule_config import (
    apply_schedule_config,
    load_schedule_config,
    parse_schedule_jobs,
    schedule_from_config,
)


class TestScheduleConfig:
    def test_parse_jobs(self):
        data = {
            "jobs": [
                {"name": "hourly", "cron": "0 * * * *", "program": "pre-commit"},
                {
                    "name": "nightly",
                    "cron": "0 2 * * *",
                    "program": "release",
                    "context": {"code": "def x(): pass"},
                },
            ]
        }
        jobs = parse_schedule_jobs(data)
        assert len(jobs) == 2
        assert jobs[0]["name"] == "hourly"
        assert jobs[1]["context"]["code"] == "def x(): pass"

    def test_invalid_cron_raises(self):
        with pytest.raises(ValueError, match="invalid cron"):
            parse_schedule_jobs({"jobs": [{"name": "bad", "cron": "nope", "program": "x"}]})

    def test_load_json_config(self, tmp_path):
        config = {
            "jobs": [{"name": "hourly", "cron": "0 * * * *", "program": "pre-commit"}]
        }
        path = tmp_path / "schedule.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        jobs = load_schedule_config(path)
        assert len(jobs) == 1

    def test_schedule_from_config(self, tmp_path):
        runtime = DevRuntime.create(use_mock=True)
        config = {
            "jobs": [{"name": "hourly", "cron": "30 14 * * *", "program": "pre-commit"}]
        }
        path = tmp_path / "schedule.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        schedule = schedule_from_config(runtime, path)
        assert len(schedule.jobs) == 1
        results = schedule.run_due(dt=datetime(2026, 7, 29, 14, 30))
        assert len(results) == 1
        assert results[0].success

    def test_library_schedule(self, tmp_path):
        runtime = DevRuntime.create(use_mock=True)
        programs_dir = tmp_path / "programs"
        programs_dir.mkdir()
        program = {
            "name": "custom-audit",
            "tasks": [{"name": "review", "action": "review"}],
        }
        (programs_dir / "custom-audit.json").write_text(json.dumps(program), encoding="utf-8")

        config = {
            "jobs": [{"name": "audit", "cron": "30 14 * * *", "program": "custom-audit"}]
        }
        (tmp_path / "schedule.json").write_text(json.dumps(config), encoding="utf-8")

        library = ProgramLibrary(programs_dir, runtime.assistant)
        library.discover()
        schedule = library.create_schedule(runtime, tmp_path / "schedule.json")
        results = schedule.run_due(dt=datetime(2026, 7, 29, 14, 30))
        assert results[0].success

    def test_apply_schedule_config_list(self):
        runtime = DevRuntime.create(use_mock=True)
        schedule = runtime.schedule()
        config = [{"name": "job", "cron": "0 * * * *", "program": "pre-commit"}]
        apply_schedule_config(schedule, config)
        assert len(schedule.jobs) == 1
