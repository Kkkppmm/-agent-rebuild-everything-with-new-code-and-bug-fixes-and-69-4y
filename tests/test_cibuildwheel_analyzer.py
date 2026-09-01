"""Tests for CibuildwheelAnalyzer."""

from pathlib import Path

from devai.cibuildwheel_analyzer import CibuildwheelAnalyzer, CibuildwheelFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.build_meta"

[tool.cibuildwheel]
build-frontend = "http://insecure-pypi.example.com/simple"
test-command = "curl -s https://install.example.com/setup.sh | bash && pytest"
before-all = "chmod 777 /tmp && rm -rf /"
test-skip = "*"
TWINE_PASSWORD = "super-secret-password"

[tool.cibuildwheel.linux]
manylinux-x86_64-image = "manylinux2014:latest"
"""

INSECURE_CIBW_TOML = """\
[tool.cibuildwheel]
test-command = ""
index-url = "http://pypi.example.com/simple"
CIBW_PASSWORD = "secret-token-here"
"""

HARDENED_PYPROJECT = """\
[tool.cibuildwheel]
build-frontend = "pip"
test-command = "pytest {project}/tests"
"""


class TestCibuildwheelAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_cibuildwheel_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "plain"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "test_skip_all" in kinds
        assert "hardcoded_secret" in kinds
        assert "latest_image" in kinds
        assert "dangerous_command" in kinds
        assert "insecure_build_frontend" in kinds

    def test_detects_cibuildwheel_toml(self, tmp_path: Path):
        (tmp_path / "cibuildwheel.toml").write_text(INSECURE_CIBW_TOML, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "disabled_tests" in kinds
        assert "insecure_http" in kinds
        assert "cibw_env_secret" in kinds

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert "1 config" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Cibuildwheel analysis:" in ctx
        assert "health score" in ctx

    def test_generate_hardened_config(self):
        analyzer = CibuildwheelAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "cibuildwheel" in config
        assert "test-command" in config

    def test_finding_format(self):
        finding = CibuildwheelFinding(
            kind="test",
            severity="high",
            message="example",
            path="pyproject.toml",
            lineno=1,
        )
        assert "[high]" in finding.format()

    def test_facade_cibuildwheel_method(self):
        import devai

        dev = devai.DevAI.mock()
        analyzer = dev.cibuildwheel(".")
        assert isinstance(analyzer, CibuildwheelAnalyzer)
