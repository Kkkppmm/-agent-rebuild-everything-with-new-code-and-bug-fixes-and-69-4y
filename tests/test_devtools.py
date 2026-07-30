"""Tests for DevTools static analysis modules."""

from pathlib import Path

import pytest

from devai.devtools import DevTools
from devai.import_graph import ImportGraph
from devai.secrets import SecretsScanner
from devai.typing_coverage import TypingCoverage
from devai.docstring_coverage import DocstringCoverage
from devai.deps_parser import DependencyParser
from devai.composer import ProgramComposer
from devai.schedule_config import load_schedule_config, apply_schedule_config
from devai import DevRuntime


class TestImportGraph:
    def test_scan_simple_project(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "a.py").write_text("import os\nimport b\n", encoding="utf-8")
        (pkg / "b.py").write_text("import a\n", encoding="utf-8")

        graph = ImportGraph(pkg)
        edges = graph.scan()
        assert len(edges) >= 2

        cycles = graph.find_cycles()
        assert len(cycles) >= 1

    def test_summary(self, tmp_path: Path):
        (tmp_path / "mod.py").write_text("import json\n", encoding="utf-8")
        graph = ImportGraph(tmp_path)
        summary = graph.summary()
        assert summary["modules"] >= 1
        assert summary["edges"] >= 1


class TestSecretsScanner:
    def test_detects_api_key(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "API_KEY = 'sk-abcdefghijklmnop1234567890'\n", encoding="utf-8"
        )
        scanner = SecretsScanner(tmp_path)
        findings = scanner.scan()
        assert len(findings) >= 1
        assert findings[0].kind == "generic_api_key"

    def test_clean_file_no_findings(self, tmp_path: Path):
        (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
        scanner = SecretsScanner(tmp_path)
        findings = scanner.scan()
        assert len(findings) == 0


class TestTypingCoverage:
    def test_analyze_typed_file(self, tmp_path: Path):
        (tmp_path / "typed.py").write_text(
            "def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8"
        )
        coverage = TypingCoverage(tmp_path)
        reports = coverage.analyze()
        assert len(reports) == 1
        assert reports[0].overall_coverage == 1.0

    def test_summary(self, tmp_path: Path):
        (tmp_path / "fn.py").write_text("def foo(x):\n    pass\n", encoding="utf-8")
        summary = TypingCoverage(tmp_path).summary()
        assert summary["files"] == 1
        assert summary["overall_coverage"] < 1.0


class TestDocstringCoverage:
    def test_documented_module(self, tmp_path: Path):
        (tmp_path / "doc.py").write_text(
            '"""Module doc."""\ndef foo():\n    """Fn doc."""\n    pass\n',
            encoding="utf-8",
        )
        coverage = DocstringCoverage(tmp_path)
        reports = coverage.analyze()
        assert len(reports) == 1
        assert reports[0].overall_coverage == 1.0

    def test_missing_docstrings(self, tmp_path: Path):
        (tmp_path / "nodoc.py").write_text("def bar(): pass\n", encoding="utf-8")
        missing = DocstringCoverage(tmp_path).missing()
        assert any(m["name"] == "bar" for m in missing)


class TestDependencyParser:
    def test_parse_requirements(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text(
            "httpx>=0.27.0\npydantic>=2.0.0\n", encoding="utf-8"
        )
        parser = DependencyParser(tmp_path)
        deps = parser.parse()
        names = {d.name.lower() for d in deps}
        assert "httpx" in names
        assert "pydantic" in names

    def test_parse_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "test"\ndependencies = ["requests>=2.0"]\n',
            encoding="utf-8",
        )
        deps = DependencyParser(tmp_path).parse()
        assert any(d.name.lower() == "requests" for d in deps)


class TestProgramComposer:
    def test_build_program(self):
        runtime = DevRuntime.create(use_mock=True)
        composer = ProgramComposer("audit", runtime.assistant)
        program = (
            composer
            .step("review", "review")
            .step("security", "security_audit", input_key="review")
            .describe("Security audit workflow")
            .tag("security", "audit")
            .build()
        )
        assert program.name == "audit"
        assert len(program.tasks) == 2
        assert program.tasks[0].action == "review"

    def test_to_dict(self):
        runtime = DevRuntime.create(use_mock=True)
        data = ProgramComposer("test", runtime.assistant).step("s1", "review").to_dict()
        assert data["name"] == "test"
        assert len(data["tasks"]) == 1


class TestScheduleConfig:
    def test_load_json_config(self, tmp_path: Path):
        config = tmp_path / "schedule.json"
        config.write_text(
            '{"jobs": [{"name": "audit", "cron": "0 * * * *", "preset": "pre-commit"}]}',
            encoding="utf-8",
        )
        jobs = load_schedule_config(config)
        assert len(jobs) == 1
        assert jobs[0]["name"] == "audit"

    def test_apply_to_schedule(self, tmp_path: Path):
        config = tmp_path / "schedule.json"
        config.write_text(
            '{"jobs": [{"name": "nightly", "cron": "0 2 * * *", "preset": "pre-commit"}]}',
            encoding="utf-8",
        )
        runtime = DevRuntime.create(use_mock=True)
        schedule = runtime.schedule()
        added = apply_schedule_config(schedule, load_schedule_config(config))
        assert added == ["nightly"]
        assert len(schedule.jobs) == 1

    def test_invalid_config_raises(self, tmp_path: Path):
        config = tmp_path / "bad.json"
        config.write_text('{"jobs": [{"name": "x"}]}', encoding="utf-8")
        with pytest.raises(ValueError):
            load_schedule_config(config)


class TestDevTools:
    def test_full_report(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            '"""App module."""\ndef main() -> None:\n    """Run."""\n    pass\n',
            encoding="utf-8",
        )
        (tmp_path / "requirements.txt").write_text("httpx>=0.27\n", encoding="utf-8")
        tools = DevTools(tmp_path)
        report = tools.full_report()
        assert report.project_path == str(tmp_path.resolve())
        assert report.dependencies["total"] >= 1

    def test_runtime_devtools(self):
        runtime = DevRuntime.create(use_mock=True)
        tools = runtime.devtools()
        assert tools is not None

    def test_runtime_composer(self):
        runtime = DevRuntime.create(use_mock=True)
        composer = runtime.composer("my-program")
        assert composer.name == "my-program"
