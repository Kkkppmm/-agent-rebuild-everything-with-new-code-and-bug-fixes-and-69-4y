"""Tests for ProgramLibrary."""

import json

import pytest

from devai import CodeAssistant, DevProgram, ProgramLibrary
from devai.core import MockLLMClient


class TestProgramLibrary:
    def test_discover_programs(self, tmp_path):
        programs_dir = tmp_path / "programs"
        programs_dir.mkdir()
        (programs_dir / "review.json").write_text(
            json.dumps(
                {
                    "name": "quick-review",
                    "description": "Fast code review",
                    "tasks": [{"name": "review", "action": "review"}],
                }
            ),
            encoding="utf-8",
        )
        (programs_dir / "security.json").write_text(
            json.dumps(
                {
                    "name": "security-scan",
                    "tasks": [{"name": "security", "action": "security"}],
                }
            ),
            encoding="utf-8",
        )

        assistant = CodeAssistant(client=MockLLMClient())
        library = ProgramLibrary(programs_dir, assistant)
        entries = library.discover()

        assert len(entries) == 2
        names = {entry.name for entry in entries}
        assert "quick-review" in names
        assert "security-scan" in names

    def test_get_and_run(self, tmp_path):
        programs_dir = tmp_path / "programs"
        programs_dir.mkdir()
        (programs_dir / "audit.json").write_text(
            json.dumps(
                {
                    "name": "audit",
                    "tasks": [
                        {"name": "review", "action": "review"},
                        {"name": "security", "action": "security"},
                    ],
                }
            ),
            encoding="utf-8",
        )

        client = MockLLMClient(responses=["Reviewed", "Secured"])
        assistant = CodeAssistant(client=client)
        library = ProgramLibrary(programs_dir, assistant)
        library.discover()

        program = library.get("audit")
        assert program.name == "audit"
        assert len(program.tasks) == 2

        results = library.run("audit", {"code": "def foo(): pass"})
        assert len(results) == 2
        assert results[0].output == "Reviewed"

    def test_search(self, tmp_path):
        programs_dir = tmp_path / "programs"
        programs_dir.mkdir()
        (programs_dir / "pr.json").write_text(
            json.dumps(
                {
                    "name": "pr-review",
                    "description": "Pull request review",
                    "tags": ["ci", "review"],
                    "tasks": [{"name": "diff", "action": "review_diff", "input_key": "diff"}],
                }
            ),
            encoding="utf-8",
        )

        assistant = CodeAssistant(client=MockLLMClient())
        library = ProgramLibrary(programs_dir, assistant)
        library.discover()

        matches = library.search("pull request")
        assert len(matches) == 1
        assert matches[0].name == "pr-review"

        matches = library.search("review_diff")
        assert len(matches) == 1

    def test_validate_all(self, tmp_path):
        programs_dir = tmp_path / "programs"
        programs_dir.mkdir()
        (programs_dir / "valid.json").write_text(
            json.dumps(
                {
                    "name": "valid",
                    "tasks": [{"name": "review", "action": "review"}],
                }
            ),
            encoding="utf-8",
        )

        assistant = CodeAssistant(client=MockLLMClient())
        library = ProgramLibrary(programs_dir, assistant)
        library.discover()
        results = library.validate_all()
        assert results["valid"] == []

    def test_get_missing_raises(self, tmp_path):
        assistant = CodeAssistant(client=MockLLMClient())
        library = ProgramLibrary(tmp_path, assistant)
        with pytest.raises(KeyError, match="not found"):
            library.get("missing")

    def test_discover_missing_dir(self, tmp_path):
        assistant = CodeAssistant(client=MockLLMClient())
        library = ProgramLibrary(tmp_path / "nope", assistant)
        with pytest.raises(FileNotFoundError):
            library.discover()
