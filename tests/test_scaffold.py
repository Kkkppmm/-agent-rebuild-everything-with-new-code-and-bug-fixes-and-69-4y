"""Tests for project scaffolding."""

from pathlib import Path

from devai.scaffold import scaffold_project


class TestScaffoldProject:
    def test_creates_default_layout(self, tmp_path: Path) -> None:
        result = scaffold_project(tmp_path)

        assert result.ok
        assert (tmp_path / ".devai.yaml").is_file()
        assert (tmp_path / "programs" / "pre-commit.yaml").is_file()
        assert (tmp_path / "devai-schedule.yaml").is_file()
        assert (tmp_path / "devai_main.py").is_file()
        assert len(result.created) == 4
        assert result.skipped == []

    def test_skips_existing_files(self, tmp_path: Path) -> None:
        scaffold_project(tmp_path)
        result = scaffold_project(tmp_path)

        assert result.created == []
        assert len(result.skipped) == 4

    def test_force_overwrites(self, tmp_path: Path) -> None:
        scaffold_project(tmp_path, model="gpt-4o-mini")
        result = scaffold_project(tmp_path, model="gpt-4o", force=True)

        assert len(result.created) == 4
        assert "gpt-4o" in (tmp_path / ".devai.yaml").read_text(encoding="utf-8")

    def test_minimal_scaffold(self, tmp_path: Path) -> None:
        result = scaffold_project(
            tmp_path,
            include_schedule=False,
            include_starter=False,
        )

        assert len(result.created) == 2
        assert not (tmp_path / "devai-schedule.yaml").exists()
        assert not (tmp_path / "devai_main.py").exists()
