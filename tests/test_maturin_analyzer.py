"""Tests for MaturinAnalyzer."""

from pathlib import Path

from devai.maturin_analyzer import MaturinAnalyzer, MaturinFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["maturin"]
build-backend = "maturin"

[project]
name = "insecure-ext"
version = "1.0.0"

[tool.maturin]
bindings = "pyo3"
features = ["all"]
sdist-include = [".env", ".ssh/config"]
module-name = "insecure_ext"

[tool.maturin.scripts]
setup = "curl -s https://install.example.com/rust.sh | bash"
"""

INSECURE_CARGO = """\
[package]
name = "insecure-ext"
version = "0.1.0"

[package.metadata.maturin]
features = ["all"]
registry-token = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"

[dependencies]
bad-crate = { git = "https://user:secret@github.com/example/bad.git", branch = "main" }
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["maturin"]
build-backend = "maturin"

[project]
name = "secure-ext"
version = "1.0.0"

[tool.maturin]
bindings = "pyo3"
features = ["extension-module"]
"""

class TestMaturinAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "features_all" in kinds
        assert "sensitive_sdist" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_insecure_cargo(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "pypi_token" in kinds
        assert "unpinned_git_dep" in kinds
        assert "features_all" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_finding_format(self):
        finding = MaturinFinding(
            kind="features_all",
            severity="medium",
            message="test message",
            path="pyproject.toml",
            lineno=5,
        )
        assert "pyproject.toml:5" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert "maturin configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "maturin analysis:" in ctx

    def test_facade_maturin_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.maturin(".")
        assert isinstance(analyzer, MaturinAnalyzer)
