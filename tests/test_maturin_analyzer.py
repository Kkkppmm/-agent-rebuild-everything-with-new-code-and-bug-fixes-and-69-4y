"""Tests for MaturinAnalyzer."""

from pathlib import Path

import devai
from devai.maturin_analyzer import MaturinAnalyzer, MaturinFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "insecure-native"
version = "1.0.0"

[tool.maturin]
module-name = "insecure_native._core"
python-source = "python"
include = [".env", "credentials.json"]
auditwheel = "skip"
strip = false
features = ["dangerous-debug"]
cargo-extra-args = "--features debug --config net.git-fetch-with-cli=true"

[tool.maturin.sdist]
include = [".ssh/id_rsa"]
"""

INSECURE_CARGO = """\
[package]
name = "insecure-native"
version = "1.0.0"

[lib]
name = "insecure_native"
crate-type = ["cdylib"]

[dependencies]
serde = { git = "https://user:secret-token@github.com/example/serde.git", branch = "main" }
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "secure-native"
version = "1.0.0"
requires-python = ">=3.10"

[tool.maturin]
module-name = "secure_native._core"
python-source = "python"
bindings = "PyO3"
features = ["abi3-py310"]
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

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "sensitive_include" in kinds
        assert "auditwheel_skip" in kinds
        assert "strip_disabled" in kinds
        assert "unsafe_feature" in kinds
        assert "dangerous_cargo_args" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_pypi_token(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["maturin"]\nbuild-backend = "maturin"\n'
            "[tool.maturin]\n"
            'token = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"\n',
            encoding="utf-8",
        )
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "pypi_token" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() >= 90.0

    def test_finding_format(self):
        finding = MaturinFinding(
            kind="test",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=1,
            line="x = 1",
        )
        assert "[high]" in finding.format()
        assert "pyproject.toml:1" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = MaturinAnalyzer(str(tmp_path))
        assert "Maturin configs:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Maturin analysis:" in context
        assert "secure_native" in context

    def test_generate_hardened_config(self):
        analyzer = MaturinAnalyzer(".")
        snippet = analyzer.generate_hardened_config()
        assert "[tool.maturin]" in snippet
        assert "MATURIN_PYPI_TOKEN" in snippet

    def test_facade_maturin(self):
        dev = devai.DevAI.mock()
        analyzer = dev.maturin(".")
        assert isinstance(analyzer, MaturinAnalyzer)
