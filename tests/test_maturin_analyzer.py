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
dependencies = ["requests>=2.0"]

[tool.maturin]
features = ["pyo3/extension-module"]
module-name = "insecure_ext"
"""

INSECURE_CARGO = """\
[package]
name = "insecure-ext"
version = "1.0.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.20", features = ["extension-module"] }
untrusted = { git = "https://user:secret-token@github.com/example/crate.git", branch = "main" }

[patch.crates-io]
serde = { git = "http://insecure-mirror.example.com/serde.git" }
"""

INSECURE_CARGO_CONFIG = """\
[registries.private]
index = "http://insecure-registry.example.com/git/index"
token = "cargo-registry-secret-token-value"

[net]
git-fetch-with-cli = true
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0,<2"]
build-backend = "maturin"

[project]
name = "secure-ext"
version = "1.0.0"
requires-python = ">=3.10"

[tool.maturin]
features = ["pyo3/extension-module"]
"""

HARDENED_CARGO = """\
[package]
name = "secure-ext"
version = "1.0.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "=0.20.3", features = ["extension-module"] }
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
        (tmp_path / "Cargo.toml").write_text(HARDENED_CARGO, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "dynamic_version" in kinds
        assert "missing_cargo_lock" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_cargo_issues(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert "patch_crates_io" in kinds
        assert "insecure_http" in kinds

    def test_detects_cargo_config_issues(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(HARDENED_CARGO, encoding="utf-8")
        cargo_config = tmp_path / ".cargo"
        cargo_config.mkdir()
        (cargo_config / "config.toml").write_text(INSECURE_CARGO_CONFIG, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "cargo_registry_token" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(HARDENED_CARGO, encoding="utf-8")
        (tmp_path / "Cargo.lock").write_text("# lockfile\n", encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_finding_format(self):
        finding = MaturinFinding(
            kind="insecure_http",
            severity="medium",
            message="test message",
            path="Cargo.toml",
            lineno=3,
        )
        assert "Cargo.toml:3" in finding.format()

    def test_parses_features_and_dependencies(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(HARDENED_CARGO, encoding="utf-8")
        (tmp_path / "Cargo.lock").write_text("# lockfile\n", encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert len(analyzer.infos) == 2
        cargo_info = next(i for i in analyzer.infos if i.file_kind == "cargo")
        assert "pyo3" in cargo_info.dependencies

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert "Maturin configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Maturin analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        analyzer = MaturinAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "maturin" in config
        assert "MATURIN_PYPI_TOKEN" in config

    def test_facade_maturin_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.maturin(".")
        assert isinstance(analyzer, MaturinAnalyzer)
