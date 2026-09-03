"""Tests for MaturinAnalyzer."""

from pathlib import Path

from devai.maturin_analyzer import MaturinAnalyzer, MaturinFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0"]
build-backend = "maturin"

[project]
name = "insecure-ext"
version = "1.0.0"

[tool.maturin]
bindings = "pyo3"
module-name = "../escape_pkg"
python-source = "../secrets"
include = [".env", ".ssh/config"]
before-build = "curl -s https://install.example.com/setup.sh | bash"
skip-auditwheel = true
MATURIN_PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"
"""

INSECURE_CARGO = """\
[package]
name = "insecure-ext"
version = "0.1.0"

[dependencies]
serde = "*"

[patch.crates-io]
foo = { git = "https://user:secret-token@github.com/example/foo.git", branch = "main" }
"""

INSECURE_MATURIN_TOML = """\
[tool.maturin]
bindings = "bin"
strip = false
index-url = "http://insecure-pypi.example.com/simple"
token = "cargo-registry-secret-token-value"
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "secure-ext"
version = "1.0.0"

[tool.maturin]
bindings = "pyo3"
module-name = "secure_ext._native"
python-source = "python"
strip = true
"""


class TestMaturinAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_maturin_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "plain"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_pyproject_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "pypi_token" in kinds
        assert "path_traversal" in kinds
        assert "sensitive_include" in kinds
        assert "curl_pipe_shell" in kinds
        assert "skip_auditwheel" in kinds
        assert "build_hook" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_cargo_toml_issues(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "dynamic_version" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert analyzer.stats.configs == 2

    def test_detects_maturin_toml_issues(self, tmp_path: Path):
        (tmp_path / "maturin.toml").write_text(INSECURE_MATURIN_TOML, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds
        assert "strip_disabled" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert high_medium == []

    def test_finding_format(self):
        finding = MaturinFinding(
            kind="path_traversal",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=3,
        )
        assert "pyproject.toml:3" in finding.format()

    def test_parses_bindings_and_features(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert len(analyzer.infos) == 1
        info = analyzer.infos[0]
        assert info.file_kind == "pyproject"
        assert "pyo3" in info.bindings

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert "maturin configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "maturin analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        analyzer = MaturinAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "[tool.maturin]" in config
        assert "MATURIN_PYPI_TOKEN" in config

    def test_facade_maturin_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.maturin(".")
        assert isinstance(analyzer, MaturinAnalyzer)
