"""Tests for program JSON Schema validation."""

import json

from devai.program_schema import (
    get_program_schema,
    get_program_schema_json,
    validate_program_dict,
)


class TestProgramSchema:
    def test_schema_structure(self):
        schema = get_program_schema()
        assert schema["title"] == "DevAI Program"
        assert "tasks" in schema["required"]

    def test_schema_json(self):
        data = json.loads(get_program_schema_json())
        assert data["type"] == "object"

    def test_valid_program_dict(self):
        data = {
            "name": "test",
            "tasks": [{"name": "review", "action": "review"}],
        }
        assert validate_program_dict(data) == []

    def test_missing_tasks(self):
        errors = validate_program_dict({"name": "bad"})
        assert any("tasks" in e for e in errors)

    def test_empty_tasks(self):
        errors = validate_program_dict({"tasks": []})
        assert any("at least one task" in e for e in errors)

    def test_duplicate_task_names(self):
        data = {
            "tasks": [
                {"name": "step", "action": "review"},
                {"name": "step", "action": "security"},
            ],
        }
        errors = validate_program_dict(data)
        assert any("duplicate" in e for e in errors)

    def test_unknown_property(self):
        data = {
            "tasks": [{"name": "x", "action": "review"}],
            "extra": True,
        }
        errors = validate_program_dict(data)
        assert any("Unknown property" in e for e in errors)

    def test_not_an_object(self):
        assert validate_program_dict([]) == ["Program must be a JSON object"]
