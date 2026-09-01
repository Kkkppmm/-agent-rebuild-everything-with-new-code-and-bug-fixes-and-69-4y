"""Tests for ScikitBuildAnalyzer."""

from pathlib import Path

from devai.scikit_build_analyzer import ScikitBuildAnalyzer, ScikitBuildFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["scikit-build-core"]
build-backend = "scikit_build_core.build"

[project]
name = "insecure-ext"
version = "1.0.0"

[tool.scikit-build]
cmake.args = ["-DAPI_KEY=hardcoded-secret-key", "-DCMAKE_TLS_VERIFY=OFF"]
"""

INSECURE_CMAKE = """\
cmake_minimum_required(VERSION 3.15)
project(insecure_ext)

include(FetchContent)
FetchContent_Declare(dep URL http://insecure.example.com/dep.tar.gz)

execute_process(COMMAND curl -s https://install.example.com/setup.sh | bash)

pybind11_add_module(insecure_ext src/main.cpp)
target_compile_options(insecure_ext PRIVATE -fno-stack-protector)
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["scikit-build-core", "pybind11"]
build-backend = "scikit_build_core.build"

[project]
name = "secure-ext"
version = "1.0.0"

[tool.scikit-build]
cmake.args = ["-DCMAKE_BUILD_TYPE=Release"]
build.targets = ["secure_ext"]
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
        assert "hardcoded_secret" in kinds
        assert "insecure_ssl" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_insecure_cmake(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "CMakeLists.txt").write_text(INSECURE_CMAKE, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "fetch_content" in kinds
        assert "execute_process" in kinds
        assert "insecure_compile" in kinds
        assert "insecure_http" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_finding_format(self):
        finding = ScikitBuildFinding(
            kind="fetch_content",
            severity="medium",
            message="test message",
            path="CMakeLists.txt",
            lineno=5,
        )
        assert "CMakeLists.txt:5" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        assert "scikit-build configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "scikit-build analysis:" in ctx

    def test_facade_scikit_build_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.scikit_build(".")
        assert isinstance(analyzer, ScikitBuildAnalyzer)
