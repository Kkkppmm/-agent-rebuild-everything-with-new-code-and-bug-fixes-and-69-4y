"""Tests for DevAI DependencyParser."""

from pathlib import Path

from devai.deps_parser import Dependency, DependencyParser


class TestDependencyParser:
    def test_parse_requirements_txt(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text(
            "httpx>=0.27.0\npydantic==2.0.0\n# comment\n-r other.txt\n",
            encoding="utf-8",
        )
        parser = DependencyParser(str(tmp_path))
        deps = parser.parse()
        names = {d.name for d in deps}
        assert "httpx" in names
        assert "pydantic" in names
        pinned = [d for d in deps if d.name == "pydantic"][0]
        assert pinned.pinned
        unpinned = [d for d in deps if d.name == "httpx"][0]
        assert not unpinned.pinned

    def test_parse_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            """
[project]
name = "demo"
dependencies = [
    "httpx>=0.27.0",
    "pydantic>=2.0.0",
]
""",
            encoding="utf-8",
        )
        parser = DependencyParser(str(tmp_path))
        deps = parser.parse()
        assert len(deps) == 2

    def test_unpinned_and_duplicates(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("httpx>=0.27.0\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = [\"httpx>=0.28.0\"]\n",
            encoding="utf-8",
        )
        parser = DependencyParser(str(tmp_path))
        assert len(parser.unpinned()) == 2
        dupes = parser.duplicates()
        assert "httpx" in dupes

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
        parser = DependencyParser(str(tmp_path))
        assert "Dependencies:" in parser.summary()
        context = parser.to_context()
        assert "requests" in context

    def test_dependency_format(self):
        dep = Dependency(name="httpx", version="0.27.0", operator=">=", source="requirements.txt")
        assert "httpx" in dep.format()
        assert "0.27.0" in dep.format()
