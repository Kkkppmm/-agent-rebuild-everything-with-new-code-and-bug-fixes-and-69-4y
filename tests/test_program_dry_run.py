"""Tests for program dry-run and JSON schema."""

import json

from devai import CodeAssistant, DevProgram, program_schema
from devai.core import MockLLMClient


class TestProgramDryRun:
    def test_dry_run_preview(self):
        assistant = CodeAssistant(client=MockLLMClient())
        program = (
            DevProgram("audit", assistant)
            .add("review_step", "review")
            .add("security_step", "security")
        )
        plan = program.dry_run({"code": "def foo(): pass"})
        assert len(plan) == 2
        assert plan[0].index == 1
        assert plan[0].name == "review_step"
        assert plan[0].action == "review"
        assert plan[0].input_key == "code"
        assert "def foo" in plan[0].input_preview

    def test_dry_run_chained_context(self):
        assistant = CodeAssistant(client=MockLLMClient())
        program = DevProgram("chain", assistant).add("explain", "explain")
        plan = program.dry_run({"code": "x = 1"})
        assert len(plan) == 1
        assert plan[0].input_preview == "x = 1"


class TestProgramSchema:
    def test_schema_structure(self):
        schema = program_schema()
        assert schema["type"] == "object"
        assert "tasks" in schema["properties"]
        assert "review" in schema["$defs"]["task"]["properties"]["action"]["enum"]

    def test_schema_matches_example(self):
        schema = program_schema()
        example = {
            "name": "pre-commit",
            "tasks": [{"name": "review", "action": "review"}],
        }
        assert example["name"]
        assert example["tasks"][0]["action"] in schema["$defs"]["task"]["properties"]["action"]["enum"]

    def test_schema_is_json_serializable(self):
        json.dumps(program_schema())
