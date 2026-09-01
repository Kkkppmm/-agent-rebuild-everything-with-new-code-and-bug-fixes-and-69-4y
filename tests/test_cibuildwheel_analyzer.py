"""Tests for CibuildwheelAnalyzer."""

from pathlib import Path

from devai.cibuildwheel_analyzer import CibuildwheelAnalyzer, CibuildwheelFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["cibuildwheel"]
build-backend = "cibuildwheel"

[project]
name = "insecure-wheel"
version = "1.0.0"

[tool.cibuildwheel]
before-build = "curl -s https://install.example.com/setup.sh | bash"
test-command = "pytest {project}/tests"
CIBW_ENVIRONMENT = "TWINE_PASSWORD=super-secret-password"

[tool.cibuildwheel.linux]
repair-command = ""
test-skip = "*"

[tool.cibuildwheel.macos]
environment = { index-url = "http://insecure-pypi.example.com/simple" }
"""

HARDENED_PYPROJECT = """\
[project]
name = "secure-wheel"
version = "1.0.0"

[tool.cibuildwheel]
test-command = "pytest {project}/tests"

[tool.cibuildwheel.linux]
repair-command = "auditwheel repair -w {dest_dir} {wheel}"
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
        assert "build_env_secret" in kinds
        assert "skip_all_tests" in kinds
        assert "disabled_repair" in kinds
        assert "insecure_http" in kinds
        assert analyzer.health_score() < 100.0

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_finding_format(self):
        finding = CibuildwheelFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=3,
        )
        assert "pyproject.toml:3" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert "cibuildwheel configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "cibuildwheel analysis:" in ctx
        assert "health score:" in ctx

    def test_facade_cibuildwheel_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.cibuildwheel(".")
        assert isinstance(analyzer, CibuildwheelAnalyzer)
