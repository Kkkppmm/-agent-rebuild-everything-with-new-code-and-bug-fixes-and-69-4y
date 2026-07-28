"""JSON Schema for DevAI program file validation."""

from __future__ import annotations

import json
from typing import Any

PROGRAM_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://devai.dev/schemas/program.json",
    "title": "DevAI Program",
    "type": "object",
    "required": ["tasks"],
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "tasks": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["name", "action"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "action": {"type": "string", "minLength": 1},
                    "input_key": {"type": "string"},
                    "kwargs": {"type": "object"},
                },
                "additionalProperties": False,
            },
        },
    },
    "additionalProperties": False,
}


def get_program_schema() -> dict[str, Any]:
    """Return a copy of the DevAI program JSON Schema."""
    return dict(PROGRAM_SCHEMA)


def get_program_schema_json() -> str:
    """Return the DevAI program JSON Schema as a formatted JSON string."""
    return json.dumps(PROGRAM_SCHEMA, indent=2)


def validate_program_dict(data: Any) -> list[str]:
    """Validate a program dictionary against the JSON Schema structure.

    Uses built-in validation only — no external jsonschema dependency.
    """
    errors: list[str] = []

    if not isinstance(data, dict):
        return ["Program must be a JSON object"]

    allowed_keys = {"name", "description", "tasks"}
    for key in data:
        if key not in allowed_keys:
            errors.append(f"Unknown property '{key}'")

    if "tasks" not in data:
        errors.append("Missing required property 'tasks'")
    elif not isinstance(data["tasks"], list):
        errors.append("Property 'tasks' must be an array")
    elif len(data["tasks"]) == 0:
        errors.append("Program must have at least one task")
    else:
        seen_names: set[str] = set()
        for index, task in enumerate(data["tasks"]):
            prefix = f"Task {index + 1}"
            if not isinstance(task, dict):
                errors.append(f"{prefix}: must be an object")
                continue
            allowed_task_keys = {"name", "action", "input_key", "kwargs"}
            for key in set(task.keys()) - allowed_task_keys:
                errors.append(f"{prefix}: unknown property '{key}'")
            name = task.get("name")
            if name is None:
                errors.append(f"{prefix}: missing required property 'name'")
            elif not isinstance(name, str) or not name.strip():
                errors.append(f"{prefix}: name must be a non-empty string")
            elif name in seen_names:
                errors.append(f"{prefix}: duplicate task name '{name}'")
            else:
                seen_names.add(name)
            action = task.get("action")
            if action is None:
                errors.append(f"{prefix}: missing required property 'action'")
            elif not isinstance(action, str) or not action.strip():
                errors.append(f"{prefix}: action must be a non-empty string")
            if "input_key" in task and not isinstance(task["input_key"], str):
                errors.append(f"{prefix}: input_key must be a string")
            if "kwargs" in task and not isinstance(task["kwargs"], dict):
                errors.append(f"{prefix}: kwargs must be an object")

    if "name" in data and not isinstance(data["name"], str):
        errors.append("Property 'name' must be a string")
    if "description" in data and not isinstance(data["description"], str):
        errors.append("Property 'description' must be a string")

    return errors
