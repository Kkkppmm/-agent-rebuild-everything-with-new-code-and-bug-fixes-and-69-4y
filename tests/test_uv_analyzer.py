"""Tests for UvAnalyzer."""

from pathlib import Path

from devai.uv_analyzer import UvAnalyzer, UvFinding


INSECURE_PYPROJECT = """\
[project]
name = "demo"
version = "0.1.0"

[tool.uv]
index-url = "http://insecure-pypi.example.com/simple/"
extra-index-url = "https://deploy:pypi-hardcoded-password@private.pypi.example/simple/"

[tool.uv.sources]
bad-lib = { git = "https://user:secret-token@github.com/example/bad-lib.git", branch = "main" }

[tool.uv.pip]
trusted-host = "insecure-pypi.example.com"
native-tls = false
password = "hardcoded-uv-password"

[tool.uv.scripts]
install = "curl -s https://install.example.com/script.sh | bash"
"""

INSECURE_UV_TOML = """\
[pip]
index-url = "http://mirror.example.com/simple/"
cert = false
system = true
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"
version = "0.1.0"
dependencies = [
    "requests==2.31.0",
    "flask==3.0.0",
]

[tool.uv]
dev-dependencies = [
    "pytest==8.0.0",
]
"""


class TestUvAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = UvAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_uv_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "uv.lock").write_text("# lock\n", encoding="utf-8")
        analyzer = UvAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        (tmp_path / "uv.toml").write_text(INSECURE_UV_TOML, encoding="utf-8")
        analyzer = UvAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "curl_pipe_shell" in kinds
        assert "insecure_ssl" in kinds
        assert "unpinned_git_dep" in kinds
        assert "trusted_host" in kinds
        assert "system_python" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "uv.lock").write_text("# lock\n", encoding="utf-8")
        analyzer = UvAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = UvAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, UvFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = UvAnalyzer(str(tmp_path))
        assert "Uv configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Uv analysis:" in context
        assert "dependencies:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = UvAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "uv.toml" in config
        assert "UV_INDEX_URL" in config

    def test_detects_missing_lockfile(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = UvAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "missing_lockfile" in kinds

    def test_uv_toml_config(self, tmp_path: Path):
        (tmp_path / "uv.toml").write_text(INSECURE_UV_TOML, encoding="utf-8")
        analyzer = UvAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
