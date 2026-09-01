"""Tests for ScikitBuildAnalyzer."""

from pathlib import Path

from devai.scikit_build_analyzer import ScikitBuildAnalyzer, ScikitBuildFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["scikit-build-core>=0.9"]
build-backend = "scikit_build_core.build"

[project]
name = "insecure-ext"
version = "1.0.0"

[tool.scikit-build]
cmake.version = ">=3.15"
cmake.source-dir = "../escape"
wheel.packages = [".env", ".ssh/config"]
metadata.version.provider = "scikit_build_core.metadata.setuptools_scm"
"""

INSECURE_CMAKE = """\
cmake_minimum_required(VERSION 3.15)
project(insecure_ext)

execute_process(
    COMMAND curl -s https://install.example.com/setup.sh | bash
)

include(FetchContent)
FetchContent_Declare(
    dep
    GIT_REPOSITORY https://user:secret-token@github.com/example/dep.git
    GIT_BRANCH main
)

add_subdirectory(../outside)
set(CMAKE_TLS_VERIFY OFF)
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["scikit-build-core>=0.9,<1.0"]
build-backend = "scikit_build_core.build"

[project]
name = "secure-ext"
version = "1.0.0"

[tool.scikit-build]
cmake.version = ">=3.15"
cmake.build-type = "Release"
wheel.packages = ["secure_ext"]
"""


class TestScikitBuildAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_scikit_build_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "plain"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_pyproject_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "path_traversal" in kinds
        assert "sensitive_include" in kinds
        assert "build_hook" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_cmake_issues(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "CMakeLists.txt").write_text(INSECURE_CMAKE, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "cmake_execute_process" in kinds
        assert "curl_pipe_shell" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert "path_traversal" in kinds
        assert "insecure_ssl" in kinds
        assert "fetchcontent" in kinds
        assert analyzer.stats.configs == 2

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert high_medium == []

    def test_finding_format(self):
        finding = ScikitBuildFinding(
            kind="path_traversal",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=3,
        )
        assert "pyproject.toml:3" in finding.format()

    def test_parses_packages_and_cmake_version(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert len(analyzer.infos) == 1
        info = analyzer.infos[0]
        assert info.file_kind == "pyproject"
        assert info.cmake_version == ">=3.15"
        assert "secure_ext" in info.packages

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        assert "scikit-build configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "scikit-build analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        analyzer = ScikitBuildAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "[tool.scikit-build]" in config
        assert "TWINE_PASSWORD" in config

    def test_facade_scikit_build_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.scikit_build(".")
        assert isinstance(analyzer, ScikitBuildAnalyzer)
