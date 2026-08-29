"""Tests for CargoAnalyzer."""

from pathlib import Path

from devai.cargo_analyzer import CargoAnalyzer, CargoFinding


INSECURE_CARGO_TOML = """\
[package]
name = "demo"
version = "0.1.0"
build = "build.rs"

[dependencies]
serde = "*"
bad-crate = { git = "https://user:secret-token@github.com/example/bad-crate.git", branch = "main" }

[build-dependencies]
curl-helper = { version = "1.0", registry = "private" }

[[bin]]
name = "demo"
path = "src/main.rs"
"""

INSECURE_CARGO_CONFIG = """\
[registries.private]
index = "http://insecure-crates.example.com/"
token = "hardcoded-cargo-registry-token-abcdefghijklmnopqrst"

[net]
git-fetch-with-cli = true

[http]
check-revoke = false
password = hardcoded-cargo-password
"""

HARDENED_CARGO_TOML = """\
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0.195"
tokio = { version = "1.35", features = ["full"] }
"""


class TestCargoAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CargoAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_cargo_toml(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text(HARDENED_CARGO_TOML, encoding="utf-8")
        (tmp_path / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
        analyzer = CargoAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        cargo_dir = tmp_path / ".cargo"
        cargo_dir.mkdir()
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO_TOML, encoding="utf-8")
        (cargo_dir / "config.toml").write_text(INSECURE_CARGO_CONFIG, encoding="utf-8")
        analyzer = CargoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "registry_token" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert "dynamic_version" in kinds
        assert "insecure_ssl" in kinds
        assert "git_fetch_cli" in kinds
        assert "missing_lockfile" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text(HARDENED_CARGO_TOML, encoding="utf-8")
        (tmp_path / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
        analyzer = CargoAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO_TOML, encoding="utf-8")
        analyzer = CargoAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, CargoFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text(INSECURE_CARGO_TOML, encoding="utf-8")
        analyzer = CargoAnalyzer(str(tmp_path))
        assert "Cargo configs:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Cargo analysis:" in context
        assert "dependencies:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = CargoAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "git-fetch-with-cli = false" in config
        assert "CARGO_REGISTRY_TOKEN" in config

    def test_detects_cargo_config(self, tmp_path: Path):
        cargo_dir = tmp_path / ".cargo"
        cargo_dir.mkdir()
        (cargo_dir / "config.toml").write_text(INSECURE_CARGO_CONFIG, encoding="utf-8")
        analyzer = CargoAnalyzer(str(tmp_path))
        assert analyzer.stats.files >= 1
