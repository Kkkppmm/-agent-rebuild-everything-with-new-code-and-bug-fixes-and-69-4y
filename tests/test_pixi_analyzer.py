"""Tests for PixiAnalyzer."""

from pathlib import Path

from devai.pixi_analyzer import PixiAnalyzer, PixiFinding


INSECURE_PIXI = """\
[workspace]
name = "insecure-project"
channels = ["http://insecure-channel.example.com", "conda-forge"]
platforms = ["linux-64"]

[dependencies]
python = ">=3.10"
numpy = "*"

[pypi-dependencies]
requests = ">=2.0"
gitpkg = { git = "https://user:secret-token@github.com/example/pkg.git", branch = "main" }

[tasks]
setup = "curl -s https://install.example.com/setup.sh | bash"
"""

HARDENED_PIXI = """\
[workspace]
name = "secure-project"
channels = ["conda-forge"]
platforms = ["linux-64"]

[dependencies]
python = "3.12"
numpy = "1.26.4"

[pypi-dependencies]
requests = "==2.31.0"

[tasks]
test = "pytest"
"""


class TestPixiAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = PixiAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_pixi_toml(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "myapp"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = PixiAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pixi.toml").write_text(INSECURE_PIXI, encoding="utf-8")
        analyzer = PixiAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "dynamic_version" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert "curl_pipe_shell" in kinds
        assert "missing_lockfile" in kinds
        assert analyzer.health_score() < 100.0

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "pixi.toml").write_text(HARDENED_PIXI, encoding="utf-8")
        (tmp_path / "pixi.lock").write_text("# lockfile\n", encoding="utf-8")
        analyzer = PixiAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert high_medium == []

    def test_finding_format(self):
        finding = PixiFinding(
            kind="insecure_http",
            severity="medium",
            message="test message",
            path="pixi.toml",
            lineno=3,
        )
        assert "pixi.toml:3" in finding.format()

    def test_parses_dependencies_and_channels(self, tmp_path: Path):
        (tmp_path / "pixi.toml").write_text(HARDENED_PIXI, encoding="utf-8")
        analyzer = PixiAnalyzer(str(tmp_path))
        analyzer.analyze()
        info = analyzer.infos[0]
        assert "numpy" in info.dependencies
        assert "conda-forge" in info.channels
        assert "test" in info.tasks

    def test_generate_hardened_config(self):
        analyzer = PixiAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "conda-forge" in config
        assert "pixi.lock" in config

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pixi.toml").write_text(INSECURE_PIXI, encoding="utf-8")
        analyzer = PixiAnalyzer(str(tmp_path))
        assert "finding" in analyzer.summary().lower()
        context = analyzer.to_context()
        assert "Pixi analysis:" in context
        assert "health score" in context
