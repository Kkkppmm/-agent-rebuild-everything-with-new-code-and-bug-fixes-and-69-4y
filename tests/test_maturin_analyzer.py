"""Tests for MaturinAnalyzer."""

from pathlib import Path

from devai.maturin_analyzer import MaturinAnalyzer


INSECURE_PYPROJECT = """\
[build-system]
requires = ["maturin"]
build-backend = "maturin"

[tool.maturin]
features = ["pyo3/extension-module"]
abi3 = false
python-source = "../outside"

[project]
name = "insecure-rust"
version = "1.0.0"
dependencies = ["requests=*"]

[tool.maturin.publish]
index-url = "http://insecure-pypi.example.com/simple"
password = "super-secret-password"
"""

INSECURE_CARGO = """\
[package]
name = "insecure-rust"
version = "0.1.0"

[lib]
crate-type = ["cdylib"]

[dependencies.pyo3]
version = "*"
git = "https://user:secret@github.com/example/pyo3.git"
branch = "main"
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[tool.maturin]
features = ["pyo3/extension-module"]
abi3 = true

[project]
name = "secure-rust"
version = "1.0.0"
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
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds
        assert "abi3_disabled" in kinds
        assert "unsafe_bindings_path" in kinds

    def test_detects_insecure_cargo(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert "dynamic_version" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert "Maturin" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_config(self):
        snippet = MaturinAnalyzer(".").generate_hardened_config()
        assert "maturin" in snippet
        assert "abi3" in snippet
