"""Tests for the DevAI facade."""

from devai import DevAI
from devai.runtime import DevRuntime


class TestDevAI:
    def test_mock_factory(self):
        ai = DevAI.mock()
        assert isinstance(ai, DevAI)
        assert isinstance(ai.runtime, DevRuntime)
        assert ai.review("def add(a, b): return a + b")

    def test_delegates_assistant(self):
        ai = DevAI.mock()
        assert ai.assistant is ai.runtime.assistant

    def test_explain_and_generate(self):
        ai = DevAI.mock()
        assert ai.explain("x = 1")
        assert ai.generate("a function that adds two numbers")

    def test_debug_and_refactor(self):
        ai = DevAI.mock()
        assert ai.debug("x = 1", "NameError")
        assert ai.refactor("x=1")

    def test_run_preset_dry_run(self):
        ai = DevAI.mock()
        steps = ai.dry_run("pre-commit")
        assert len(steps) >= 1

    def test_preset_returns_program(self):
        ai = DevAI.mock()
        program = ai.preset("pre-commit")
        assert program.name

    def test_workflow(self):
        ai = DevAI.mock()
        wf = ai.workflow("test")
        assert wf.name == "test"

    def test_metrics(self):
        ai = DevAI.mock()
        metrics = ai.metrics(".")
        assert metrics is not None

    def test_docstrings_and_test_map(self, tmp_path):
        from pathlib import Path

        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("def foo(): pass\n", encoding="utf-8")

        ai = DevAI.mock()
        doc_cov = ai.docstrings(str(tmp_path))
        assert doc_cov.coverage_pct() < 100.0

        test_map = ai.test_map(str(tmp_path))
        assert test_map.map().total_modules >= 1

    def test_health(self, tmp_path):
        from pathlib import Path

        (tmp_path / "app.py").write_text("def foo(): pass\n", encoding="utf-8")
        ai = DevAI.mock()
        health = ai.health(str(tmp_path), scan_secrets=False)
        assert health.report.overall_score >= 0

    def test_getattr_delegates_to_runtime(self):
        ai = DevAI.mock()
        assert ai.kit is ai.runtime.kit
        assert ai.config is ai.runtime.config

    def test_api_surface_and_hotspots(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text('def foo():\n    """doc"""\n    return 1\n', encoding="utf-8")
        ai = DevAI.mock()
        assert ai.api_surface(str(tmp_path), source_dir="src").stats.public_symbols >= 1
        assert ai.hotspots(str(tmp_path)).stats.files_analyzed >= 1

    def test_imports_exceptions_coupling(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("import os\n\ndef foo(): return 1\n", encoding="utf-8")
        ai = DevAI.mock()
        graph = ai.imports(str(tmp_path))
        assert len(graph.build()) >= 1
        assert ai.exceptions(str(tmp_path)).health_score() >= 0
        assert ai.coupling(str(tmp_path)).health_score() >= 0
        assert ai.naming(str(tmp_path)).health_score() >= 0
        assert ai.magic_numbers(str(tmp_path)).health_score() >= 0
        assert ai.dangerous_calls(str(tmp_path)).health_score() >= 0

    def test_security_analyzers(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("def foo(): return 1\n", encoding="utf-8")
        ai = DevAI.mock()
        assert ai.secrets(str(tmp_path)).scan() is not None
        assert ai.sql_injection(str(tmp_path)).health_score() >= 0
        assert ai.debug_artifacts(str(tmp_path)).health_score() >= 0
        assert ai.async_blocking(str(tmp_path)).health_score() >= 0
        assert ai.resource_leaks(str(tmp_path)).health_score() >= 0
        assert ai.insecure_random(str(tmp_path)).health_score() >= 0
        assert ai.path_traversal(str(tmp_path)).health_score() >= 0
        assert ai.unsafe_deserialization(str(tmp_path)).health_score() >= 0
        assert ai.open_redirect(str(tmp_path)).health_score() >= 0
        assert ai.redos(str(tmp_path)).health_score() >= 0
        assert ai.hardcoded_config(str(tmp_path)).health_score() >= 0
        assert ai.timing_attack(str(tmp_path)).health_score() >= 0
        assert ai.security_scan(str(tmp_path)).health_score() == 100.0
