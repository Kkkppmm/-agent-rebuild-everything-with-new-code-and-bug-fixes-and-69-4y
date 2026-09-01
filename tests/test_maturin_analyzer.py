"""Tests for MaturinAnalyzer."""

from pathlib import Path

from devai.maturin_analyzer import MaturinAnalyzer, MaturinFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "insecure-ext"
version = "0.1.0"

[tool.maturin]
features = ["pyo3/extension-module"]
module-name = "insecure_ext._native"
before-build = "curl -s https://install.example.com/setup.sh | bash"
auditwheel = "skip"
include = [".env", "secrets.pem"]
password = "hardcoded-maturin-password"
"""

INSECURE_CARGO = """\
[package]
name = "insecure-ext"
version = "0.1.0"

[dependencies]
serde = "*"
reqwest = { git = "https://user:secret-token@github.com/example/reqwest.git", branch = "main" }

[profile.release]
RUSTFLAGS = "-C link-arg=-z norelro"
"""

INSECURE_CARGO_CONFIG = """\
[registries.private]
index = "http://insecure-registry.example.com/git/index"
token = "crates-io-hardcoded-token-value"

[net]
git-fetch-with-cli = true
http-check-revoke = false
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "secure-ext"
version = "0.1.0"

[tool.maturin]
features = ["pyo3/extension-module"]
module-name = "secure_ext._native"
exclude = [".env", "*.pem"]
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
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO, encoding="utf-8")
        cargo_dir = tmp_path / ".cargo"
        cargo_dir.mkdir()
        (cargo_dir / "config.toml").write_text(INSECURE_CARGO_CONFIG, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "auditwheel_skip" in kinds
        assert "sensitive_include" in kinds
        assert "unpinned_git_dep" in kinds
        assert "scm_credentials" in kinds
        assert "dynamic_version" in kinds
        assert "unsafe_rustflags" in kinds
        assert "insecure_http" in kinds
        assert "cargo_token" in kinds
        assert "insecure_ssl" in kinds
        assert analyzer.stats.configs == 3
        assert analyzer.health_score() < 50.0

    def test_hardened_project_low_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "secure-ext"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = MaturinFinding(
            kind="test",
            severity="high",
            message="example",
            path="pyproject.toml",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "pyproject.toml:1" in finding.format()

    def test_infos_populated(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert len(analyzer.infos) == 1
        info = analyzer.infos[0]
        assert info.file_kind == "pyproject"
        assert "pyo3/extension-module" in info.features

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert "Maturin configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Maturin analysis:" in ctx
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
