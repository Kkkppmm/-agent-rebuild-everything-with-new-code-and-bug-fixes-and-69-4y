"""Tests for PoetryAnalyzer."""

from pathlib import Path

from devai.poetry_analyzer import PoetryAnalyzer, PoetryFinding


INSECURE_PYPROJECT = """\
[tool.poetry]
name = "demo"
version = "0.1.0"
description = ""
authors = ["Dev <dev@example.com>"]

[[tool.poetry.source]]
name = "private"
url = "http://insecure-pypi.example.com/simple/"
priority = "primary"

[tool.poetry.dependencies]
python = "^3.10"
requests = "*"
bad-lib = {git = "https://user:secret-token@github.com/example/bad-lib.git", branch = "main"}

[tool.poetry.group.dev.dependencies]
pytest = ">=0"

[tool.poetry.scripts]
install-deps = "sh -c 'curl -s https://install.example.com/script.sh | bash'"

[tool.poetry]
# duplicate section marker for scripts detection
"""

INSECURE_POETRY_TOML = """\
[http-basic]
private = { username = "deploy", password = "hardcoded-pypi-password" }

[repositories]
custom = { url = "http://mirror.example.com/simple/" }

cert = false
"""

HARDENED_PYPROJECT = """\
[tool.poetry]
name = "demo"
version = "0.1.0"
description = ""
authors = ["Dev <dev@example.com>"]

[tool.poetry.dependencies]
python = "^3.10"
requests = "2.31.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
"""


class TestPoetryAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = PoetryAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_poetry_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = PoetryAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        (tmp_path / "poetry.toml").write_text(INSECURE_POETRY_TOML, encoding="utf-8")
        analyzer = PoetryAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "curl_pipe_shell" in kinds
        assert "insecure_ssl" in kinds
        assert "dynamic_version" in kinds
        assert "unpinned_git_dep" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "poetry.lock").write_text("# lock\n", encoding="utf-8")
        analyzer = PoetryAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PoetryAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, PoetryFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PoetryAnalyzer(str(tmp_path))
        assert "Poetry configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Poetry analysis:" in context
        assert "dependencies:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = PoetryAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "http-basic" in config
        assert "poetry.toml" in config

    def test_detects_missing_lockfile(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = PoetryAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "missing_lockfile" in kinds

    def test_detects_pypi_token(self, tmp_path: Path):
        pyproject = HARDENED_PYPROJECT + '\ntoken = "pypi-AgEIcHlwaS5vcmcCJDFlY2Jk..."\n'
        (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        analyzer = PoetryAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "pypi_token" in kinds
