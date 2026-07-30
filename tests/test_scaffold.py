"""Tests for DevAI project scaffolding."""

from pathlib import Path

from devai import DevAI, ScaffoldResult, scaffold_project


class TestScaffold:
    def test_scaffold_creates_layout(self, tmp_path: Path):
        target = tmp_path / "my-app"
        result = scaffold_project(target, package="myapp")
        assert isinstance(result, ScaffoldResult)
        assert (target / "pyproject.toml").exists()
        assert (target / "src" / "myapp" / "__init__.py").exists()
        assert (target / "tests" / "test_myapp.py").exists()
        assert (target / "examples" / "basic_usage.py").exists()
        assert (target / ".devai.yaml").exists()
        assert len(result.created) >= 5

    def test_scaffold_skips_existing(self, tmp_path: Path):
        target = tmp_path / "existing"
        target.mkdir()
        (target / "README.md").write_text("keep me", encoding="utf-8")
        result = scaffold_project(target, package="existing")
        assert (target / "README.md").read_text(encoding="utf-8") == "keep me"
        assert any(p.name == "README.md" for p in result.skipped)

    def test_scaffold_overwrite(self, tmp_path: Path):
        target = tmp_path / "overwrite"
        target.mkdir()
        (target / "README.md").write_text("old", encoding="utf-8")
        result = scaffold_project(target, package="overwrite", overwrite=True)
        assert "old" not in (target / "README.md").read_text(encoding="utf-8")
        assert any(p.name == "README.md" for p in result.created)

    def test_scaffold_summary(self, tmp_path: Path):
        target = tmp_path / "summary-test"
        result = scaffold_project(target, package="summarytest")
        assert "Scaffolded project" in result.summary()

    def test_devai_scaffold_classmethod(self, tmp_path: Path):
        target = tmp_path / "via-facade"
        result = DevAI.scaffold(target, package="viafacade")
        assert (target / "src" / "viafacade" / "main.py").exists()

    def test_runtime_scaffold(self, tmp_path: Path):
        from devai import DevRuntime

        target = tmp_path / "via-runtime"
        runtime = DevRuntime.create(use_mock=True)
        result = runtime.scaffold(target, package="viaruntime")
        assert (target / "src" / "viaruntime" / "__init__.py").exists()
