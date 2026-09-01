"""Tests for MaturinAnalyzer."""

from pathlib import Path

from devai.maturin_analyzer import MaturinAnalyzer


INSECURE_PYPROJECT = """\
[build-system]
requires = ["maturin"]
build-backend = "maturin"

[tool.maturin]
features = ["all"]
"""

INSECURE_CARGO = """\
[package]
name = "insecure-crate"
version = "0.1.0"

[dependencies]
evil = { git = "https://user:secret-token@github.com/example/pkg.git", branch = "main" }
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0,<2"]
build-backend = "maturin"

[tool.maturin]
features = ["pyo3/extension-module"]
"""


class TestMaturinAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_pyproject_issues(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "wildcard_features" in kinds

    def test_detects_cargo_issues(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert "maturin configs:" in analyzer.summary()
        assert "maturin analysis:" in analyzer.to_context()

    def test_generate_hardened_config(self):
        snippet = MaturinAnalyzer(".").generate_hardened_config()
        assert "[tool.maturin]" in snippet
