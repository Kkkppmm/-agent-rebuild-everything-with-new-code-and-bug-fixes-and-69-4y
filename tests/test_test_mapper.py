"""Tests for DevAI TestMapper."""

from pathlib import Path

from devai.test_mapper import ModuleMapping, TestMapper as SourceTestMapper


class TestTestMapperModule:
    def _setup_project(self, tmp_path: Path) -> None:
        src = tmp_path / "src" / "myapp"
        tests = tmp_path / "tests"
        src.mkdir(parents=True)
        tests.mkdir()

        (src / "__init__.py").write_text("", encoding="utf-8")
        (src / "utils.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
        (src / "core.py").write_text("def run():\n    pass\n", encoding="utf-8")
        (tests / "test_utils.py").write_text(
            "def test_helper():\n    assert True\n",
            encoding="utf-8",
        )

    def test_maps_source_to_tests(self, tmp_path: Path):
        self._setup_project(tmp_path)
        mapper = SourceTestMapper(str(tmp_path))
        report = mapper.map()
        assert report.total_modules == 2
        assert report.tested == 1
        assert any("core.py" in p for p in report.untested)

    def test_untested_modules(self, tmp_path: Path):
        self._setup_project(tmp_path)
        mapper = SourceTestMapper(str(tmp_path))
        untested = mapper.untested_modules()
        assert len(untested) == 1
        assert "core.py" in untested[0]

    def test_summary_and_context(self, tmp_path: Path):
        self._setup_project(tmp_path)
        mapper = SourceTestMapper(str(tmp_path))
        assert "Test mapping:" in mapper.summary()
        context = mapper.to_context()
        assert "core.py" in context

    def test_module_mapping_format(self):
        mapping = ModuleMapping(source="src/app.py", tests=["tests/test_app.py"])
        assert "test_app.py" in mapping.format()
        assert mapping.has_tests

    def test_no_tests_project(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text("x = 1\n", encoding="utf-8")
        mapper = SourceTestMapper(str(tmp_path))
        report = mapper.map()
        assert report.tested == 0
        assert report.coverage_pct == 0.0

    def test_suffix_test_pattern(self, tmp_path: Path):
        src = tmp_path / "src"
        tests = tmp_path / "tests"
        src.mkdir()
        tests.mkdir()
        (src / "parser.py").write_text("def parse(): pass\n", encoding="utf-8")
        (tests / "parser_test.py").write_text("def test_parse(): pass\n", encoding="utf-8")

        mapper = SourceTestMapper(str(tmp_path))
        report = mapper.map()
        assert report.tested == 1
