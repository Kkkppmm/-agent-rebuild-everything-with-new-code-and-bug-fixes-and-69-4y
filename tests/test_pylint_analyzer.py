"""Tests for PylintAnalyzer."""

from pathlib import Path

from devai.pylint_analyzer import PylintAnalyzer, PylintFinding


INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.pylint.main]
fail-under = 3.0
init-hook = 'import os; os.system("echo pwned")'
ignore-paths = ["**/*", "src/*"]
api_key = api_key=hardcoded_secret_value_12345

[tool.pylint."messages control"]
disable = ["all", "exec-used", "hardcoded-password"]
unsafe-load-any-extension = true
ignored-modules = *
reports = false
allow-global-unused-variables = true

[tool.pytest.ini_options]
addopts = "-q"
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.pylint.main]
fail-under = 8.0
ignore-paths = ["^\\\\.venv/.*$"]

[tool.pylint."messages control"]
disable = ["locally-disabled", "file-ignored"]

[tool.pylint.reports]
reports = true
"""

INSECURE_PYLINTRC = """\
[MASTER]
init-hook=import subprocess; subprocess.call(['ls'])
load-plugins=/tmp/untrusted_plugin
unsafe-load-any-extension=yes

[MESSAGES CONTROL]
disable=all,eval-used
ignore=src,lib

[REPORTS]
reports=no
"""

INSECURE_SETUP_CFG = """\
[metadata]
name = demo

[pylint]
fail-under = 2
disable = hardcoded-password,sql-injection
ignore-paths = app
"""


class TestPylintAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "init_hook" in kinds
        assert "disable_all" in kinds
        assert "disable_security_rules" in kinds
        assert "unsafe_load_extension" in kinds
        assert "ignore_paths_broad" in kinds
        assert "fail_under_low" in kinds
        assert "ignored_modules_broad" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_pylintrc_detected(self, tmp_path: Path):
        (tmp_path / ".pylintrc").write_text(INSECURE_PYLINTRC, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "init_hook" in kinds
        assert "disable_all" in kinds
        assert "load_plugins_untrusted_path" in kinds
        assert "ignore_source" in kinds

    def test_setup_cfg_detected(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(INSECURE_SETUP_CFG, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "fail_under_low" in kinds
        assert "disable_security_rules" in kinds
        assert "ignore_source" in kinds

    def test_no_config_returns_clean(self, tmp_path: Path):
        analyzer = PylintAnalyzer(str(tmp_path))
        assert analyzer.config_files() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_pyproject_ignores_non_pylint_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\nname = demo\n",
            encoding="utf-8",
        )
        assert PylintAnalyzer(str(tmp_path)).config_files() == []

    def test_finding_format(self):
        finding = PylintFinding(
            kind="init_hook",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=5,
        )
        assert "[high]" in finding.format()
        assert "pyproject.toml:5" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = PylintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.pylint.main]" in template
        assert "fail-under = 8.0" in template
        assert "reports = true" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[tool.pylint.main]\nfail-under = 2.0\n',
            encoding="utf-8",
        )
        analyzer = PylintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Pylint analysis:" in context
        assert "fail-under" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "pyproject.toml").write_text(
            '[tool.pylint.main]\nfail-under = 2.0\n',
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        pylint = next(c for c in report.categories if c.name == "pylint")
        assert pylint.score < 100.0
        assert pylint.details.get("findings", 0) > 0

    def test_facade_integration(self, tmp_path: Path):
        from devai import DevAI

        (tmp_path / "pyproject.toml").write_text(
            '[tool.pylint.main]\nfail-under = 2.0\n',
            encoding="utf-8",
        )
        ai = DevAI.mock()
        analyzer = ai.pylint(str(tmp_path))
        assert analyzer.health_score() < 100.0
