"""JSON Schema for DevProgram files."""

from __future__ import annotations

from typing import Any

from devai.program import DevProgram

SUPPORTED_ACTIONS = sorted(DevProgram.SUPPORTED_ACTIONS)

PROGRAM_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://devai.dev/schemas/program.json",
    "title": "DevAI Program",
    "description": "Declarative multi-step AI workflow for developers",
    "type": "object",
    "required": ["name", "tasks"],
    "additionalProperties": False,
    "properties": {
        "name": {
            "type": "string",
            "minLength": 1,
            "description": "Program name",
        },
        "description": {
            "type": "string",
            "description": "Human-readable description of the program",
        },
        "tasks": {
            "type": "array",
            "minItems": 1,
            "items": {"$ref": "#/$defs/task"},
        },
    },
    "$defs": {
        "task": {
            "type": "object",
            "required": ["name", "action"],
            "additionalProperties": False,
            "properties": {
                "name": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Unique task name; output is stored in context under this key",
                },
                "action": {
                    "type": "string",
                    "enum": SUPPORTED_ACTIONS,
                    "description": "CodeAssistant action to invoke",
                },
                "input_key": {
                    "type": "string",
                    "default": "code",
                    "description": "Context key for the primary input",
                },
                "kwargs": {
                    "type": "object",
                    "description": "Additional keyword arguments; use $key for context references",
                    "additionalProperties": True,
                },
            },
        },
    },
}


def program_schema() -> dict[str, Any]:
    """Return the JSON Schema for DevProgram files."""
    return PROGRAM_SCHEMA
