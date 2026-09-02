"""Tests for HatchAnalyzer."""

from pathlib import Path

from devai.hatch_analyzer import HatchAnalyzer, HatchFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "insecure-pkg"
version = "1.0.0"
dependencies = ["requests>=2.0"]

[tool.hatch.envs.default]
dependencies = ["pytest>=7.0"]
pre-install-commands = ["curl -s https://install.example.com/setup.sh | bash"]

[tool.hatch.publish.index]
repo = "http://insecure-pypi.example.com/simple"
user = "admin"
auth = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"

[tool.hatch.envs.test]
dependencies = [
    "git+https://user:secret-token@github.com/example/pkg.git@main",
]
"""

INSECURE_HATCH_TOML = """\
[envs.default]
dependencies = ["numpy=*"]
TWINE_PASSWORD = "super-secret-password"

[envs.ci]
index-url = "http://pypi.example.com/simple"
trusted-host = "pypi.example.com"
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "secure-pkg"
version = "1.0.0"
dependencies = ["requests==2.31.0"]

[tool.hatch.envs.default]
dependencies = ["pytest==7.4.0"]
"""


class TestHatchAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = HatchAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_hatch_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "plain"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = HatchAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = HatchAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "dynamic_version" in kinds
        assert "curl_pipe_shell" in kinds
        assert "pypi_token" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_hatch_toml_issues(self, tmp_path: Path):
        (tmp_path / "hatch.toml").write_text(INSECURE_HATCH_TOML, encoding="utf-8")
        analyzer = HatchAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "dynamic_version" in kinds
        assert "insecure_http" in kinds
        assert "trusted_host" in kinds
        assert "hardcoded_secret" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = HatchAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert high_medium == []

    def test_finding_format(self):
        finding = HatchFinding(
            kind="insecure_http",
            severity="medium",
            message="test message",
            path="pyproject.toml",
            lineno=3,
        )
        assert "pyproject.toml:3" in finding.format()

    def test_parses_envs_and_dependencies(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = HatchAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert len(analyzer.infos) == 1
        info = analyzer.infos[0]
        assert info.file_kind == "pyproject"
        assert "default" in info.envs

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = HatchAnalyzer(str(tmp_path))
        assert "Hatch configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Hatch analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        analyzer = HatchAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "hatch.toml" in config
        assert "HATCH_INDEX_AUTH" in config

    def test_facade_hatch_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.hatch(".")
        assert isinstance(analyzer, HatchAnalyzer)
