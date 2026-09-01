"""Tests for FlitAnalyzer."""

from pathlib import Path

from devai.flit_analyzer import FlitAnalyzer, FlitFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["flit_core>=3.9.0"]
build-backend = "flit_core.buildapi"

[project]
name = "insecure-pkg"
version = "1.0.0"
dependencies = ["requests>=2.0"]

[tool.flit.metadata]
module = "insecure_pkg"
home-page = "http://insecure.example.com"
requires = [
    "git+https://user:secret-token@github.com/example/pkg.git@main",
]

[tool.flit.sdist]
include = ["scripts/setup.sh"]
"""

INSECURE_FLIT_INI = """\
[metadata]
module = "../escape_pkg"
author = "Dev"
home-page = "http://pypi.example.com/simple"
PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"

[scripts]
post-install = "curl -s https://install.example.com/setup.sh | bash"
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["flit_core"]
build-backend = "flit_core.buildapi"

[project]
name = "secure-pkg"
version = "1.0.0"
dependencies = ["requests==2.31.0"]

[tool.flit.metadata]
module = "secure_pkg"
home-page = "https://example.com"
"""


class TestFlitAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = FlitAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_flit_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "plain"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = FlitAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = FlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "dynamic_version" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_flit_ini_issues(self, tmp_path: Path):
        (tmp_path / "flit.ini").write_text(INSECURE_FLIT_INI, encoding="utf-8")
        analyzer = FlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "pypi_token" in kinds
        assert "unsafe_module" in kinds
        assert "curl_pipe_shell" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = FlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert high_medium == []

    def test_finding_format(self):
        finding = FlitFinding(
            kind="insecure_http",
            severity="medium",
            message="test message",
            path="pyproject.toml",
            lineno=3,
        )
        assert "pyproject.toml:3" in finding.format()

    def test_parses_module_and_dependencies(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = FlitAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert len(analyzer.infos) == 1
        info = analyzer.infos[0]
        assert info.file_kind == "pyproject"
        assert info.module == "secure_pkg"

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = FlitAnalyzer(str(tmp_path))
        assert "Flit configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Flit analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        analyzer = FlitAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "flit_core.buildapi" in config
        assert "FLIT_PASSWORD" in config

    def test_facade_flit_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.flit(".")
        assert isinstance(analyzer, FlitAnalyzer)
