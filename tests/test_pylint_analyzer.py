"""Tests for PylintAnalyzer."""

from pathlib import Path

from devai.pylint_analyzer import PylintAnalyzer, PylintFinding


INSECURE_PYLINTRC = """\
[MASTER]
init-hook = import os; os.system('echo pwned')
unsafe-load-any-extension = yes
load-plugins = pylint_django
ignore-patterns = src, lib
allow-global-unused-variables = yes
api_key = api_key=hardcoded_secret_value_12345

[MESSAGES CONTROL]
disable = all
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.pylint.main]
unsafe-load-any-extension = false
load-plugins = []

[tool.pylint."messages control"]
disable = []
enable = ["all"]

[tool.pylint.format]
max-line-length = 88
"""

INSECURE_PYPROJECT = """\
[tool.pylint.main]
init-hook = print('hello')
disable = all

[tool.pytest.ini_options]
addopts = "-q"
"""


class TestPylintAnalyzer:
    def test_detects_insecure_pylintrc(self, tmp_path: Path):
        (tmp_path / ".pylintrc").write_text(INSECURE_PYLINTRC, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "init_hook" in kinds
        assert "disable_all" in kinds
        assert "unsafe_load_any_extension" in kinds
        assert "load_plugins" in kinds
        assert "ignore_patterns_source" in kinds
        assert "allow_global_unused_variables" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert not analyzer.infos[0].has_init_hook

    def test_pyproject_ignores_non_pylint_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "init_hook" in kinds
        assert "disable_all" in kinds
        assert all(f.lineno <= 4 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = PylintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = PylintFinding(
            kind="init_hook",
            severity="high",
            message="test message",
            path="pylintrc",
            lineno=1,
            line="init-hook = ...",
        )
        assert "[high]" in finding.format()
        assert "init_hook" not in finding.format()

    def test_generate_hardened_template(self):
        analyzer = PylintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "unsafe-load-any-extension = false" in template
        assert "disable = []" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".pylintrc").write_text(INSECURE_PYLINTRC, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Pylint analysis:" in context
        assert "init-hook=yes" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / ".pylintrc").write_text(INSECURE_PYLINTRC, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Pylint configs: 1 file(s)" in summary
