"""Schedule config — load cron job definitions from YAML/JSON config files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from devai.schedule import DevSchedule


def load_schedule_config(path: str | Path) -> list[dict[str, Any]]:
    """Load schedule job definitions from a JSON or YAML file.

    Expected format::

        {
          "jobs": [
            {"name": "nightly-audit", "cron": "0 2 * * *", "preset": "pre-commit"},
            {"name": "hourly-check", "cron": "0 * * * *", "program": "health.json"}
          ]
        }
    """
    path = Path(path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Schedule config not found: {path}")

    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML is required for YAML schedule configs. pip install pyyaml")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    if not isinstance(data, dict):
        raise ValueError(f"Schedule config must be a dict, got {type(data).__name__}")

    jobs = data.get("jobs", [])
    if not isinstance(jobs, list):
        raise ValueError("Schedule config 'jobs' must be a list")

    validated: list[dict[str, Any]] = []
    for i, job in enumerate(jobs):
        if not isinstance(job, dict):
            raise ValueError(f"Job {i} must be a dict")
        if "name" not in job or "cron" not in job:
            raise ValueError(f"Job {i} must have 'name' and 'cron' fields")
        if "preset" not in job and "program" not in job:
            raise ValueError(f"Job {i} must have 'preset' or 'program' field")
        validated.append(job)

    return validated


def schedule_from_config(schedule: "DevSchedule", config_path: str | Path) -> list[str]:
    """Load jobs from a config file and add them to a DevSchedule.

    Returns the list of added job names.
    """
    jobs = load_schedule_config(config_path)
    added: list[str] = []
    for job in jobs:
        target = job.get("preset") or job.get("program", "")
        context = job.get("context", {})
        if not isinstance(context, dict):
            context = {}
        schedule.add(job["name"], job["cron"], target, context={k: str(v) for k, v in context.items()})
        added.append(job["name"])
    return added


def apply_schedule_config(
    schedule: "DevSchedule",
    jobs: list[dict[str, Any]],
) -> list[str]:
    """Apply a list of job definitions to a DevSchedule.

    Returns the list of added job names.
    """
    added: list[str] = []
    for job in jobs:
        target = job.get("preset") or job.get("program", "")
        context = job.get("context", {})
        if not isinstance(context, dict):
            context = {}
        schedule.add(job["name"], job["cron"], target, context={k: str(v) for k, v in context.items()})
        added.append(job["name"])
    return added
