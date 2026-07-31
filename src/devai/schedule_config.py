"""Load cron schedule configurations for DevSchedule and ProgramLibrary."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TYPE_CHECKING

from devai.schedule import DevSchedule, validate_cron

if TYPE_CHECKING:
    from devai.library import ProgramLibrary
    from devai.runtime import DevRuntime


def _load_data(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required for YAML schedule configs. Install with: pip install 'devai[yaml]'"
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Schedule config must be a mapping at the top level")
    return data


def parse_schedule_jobs(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse job entries from a schedule config dict."""
    jobs = data.get("jobs", [])
    if not isinstance(jobs, list):
        raise ValueError("'jobs' must be a list")
    parsed: list[dict[str, Any]] = []
    for index, job in enumerate(jobs):
        if not isinstance(job, dict):
            raise ValueError(f"Job {index + 1} must be a mapping")
        name = job.get("name")
        cron = job.get("cron")
        program = job.get("program")
        if not name or not cron or not program:
            raise ValueError(f"Job {index + 1} requires name, cron, and program fields")
        if not validate_cron(str(cron)):
            raise ValueError(f"Job '{name}' has invalid cron expression: {cron!r}")
        context = job.get("context", {})
        if not isinstance(context, dict):
            raise ValueError(f"Job '{name}' context must be a mapping")
        parsed.append(
            {
                "name": str(name),
                "cron": str(cron),
                "program": str(program),
                "context": {str(k): str(v) for k, v in context.items()},
            }
        )
    return parsed


def load_schedule_config(path: str | Path) -> list[dict[str, Any]]:
    """Load and validate a schedule config file (JSON or YAML)."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Schedule config not found: {path}")
    return parse_schedule_jobs(_load_data(path))


def apply_schedule_config(
    schedule: DevSchedule,
    config: list[dict[str, Any]] | str | Path,
    *,
    library: ProgramLibrary | None = None,
) -> DevSchedule:
    """Register jobs from a schedule config onto an existing DevSchedule.

    Program names resolve against the runtime's registered programs and presets.
    When ``library`` is provided, program names also resolve against the library.
    """
    if not isinstance(config, list):
        config = load_schedule_config(config)

    for job in config:
        program_name = job["program"]
        target = program_name

        if library is not None:
            try:
                target = library.get(program_name)
            except KeyError:
                pass

        schedule.add(
            job["name"],
            job["cron"],
            target,
            context=job.get("context"),
        )
    return schedule


def schedule_from_config(
    runtime: DevRuntime,
    path: str | Path,
    *,
    library: ProgramLibrary | None = None,
) -> DevSchedule:
    """Create a DevSchedule from a config file and runtime."""
    schedule = runtime.schedule()
    return apply_schedule_config(schedule, path, library=library)
