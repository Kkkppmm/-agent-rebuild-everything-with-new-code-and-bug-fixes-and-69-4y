"""Tests for CondaAnalyzer."""

from pathlib import Path

from devai.conda_analyzer import CondaAnalyzer, CondaFinding


INSECURE_ENV = """\
name: insecure-env
channels:
  - http://insecure-channel.example.com
  - conda-forge
dependencies:
  - python>=3.10
  - numpy=*
  - pip:
    - requests>=2.0
    - git+https://user:secret-token@github.com/example/pkg.git@main
"""

INSECURE_RECIPE = """\
package:
  name: mypkg
  version: 1.0.0
build:
  script: curl -s https://install.example.com/setup.sh | bash
requirements:
  build:
    - python
  run:
    - numpy>=1.0
"""

HARDENED_ENV = """\
name: secure-env
channels:
  - conda-forge
dependencies:
  - python=3.10
  - numpy=1.26.4
  - pip:
    - requests==2.31.0
"""


class TestCondaAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CondaAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_conda_yaml(self, tmp_path: Path):
        (tmp_path / "docker-compose.yml").write_text(
            "version: '3'\nservices:\n  web:\n    image: nginx\n",
            encoding="utf-8",
        )
        analyzer = CondaAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "environment.yml").write_text(INSECURE_ENV, encoding="utf-8")
        analyzer = CondaAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "dynamic_version" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert "missing_lockfile" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_recipe_issues(self, tmp_path: Path):
        (tmp_path / "meta.yaml").write_text(INSECURE_RECIPE, encoding="utf-8")
        analyzer = CondaAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "dynamic_version" in kinds

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "environment.yml").write_text(HARDENED_ENV, encoding="utf-8")
        (tmp_path / "conda-lock.yml").write_text("version: 1\n", encoding="utf-8")
        analyzer = CondaAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert high_medium == []

    def test_finding_format(self):
        finding = CondaFinding(
            kind="insecure_http",
            severity="medium",
            message="test message",
            path="environment.yml",
            lineno=3,
        )
        assert "environment.yml:3" in finding.format()

    def test_parses_dependencies_and_channels(self, tmp_path: Path):
        (tmp_path / "environment.yml").write_text(HARDENED_ENV, encoding="utf-8")
        analyzer = CondaAnalyzer(str(tmp_path))
        analyzer.analyze()
        env_info = next(i for i in analyzer.infos if i.file_kind == "environment")
        assert "numpy" in env_info.dependencies
        assert "conda-forge" in env_info.channels

    def test_generate_hardened_config(self):
        analyzer = CondaAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "conda-forge" in config
        assert "conda-lock" in config

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "environment.yml").write_text(INSECURE_ENV, encoding="utf-8")
        analyzer = CondaAnalyzer(str(tmp_path))
        assert "finding" in analyzer.summary().lower()
        context = analyzer.to_context()
        assert "Conda analysis:" in context
        assert "health score" in context
