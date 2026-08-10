"""Tests for TravisCIAnalyzer."""

from pathlib import Path

from devai.travis_ci_analyzer import TravisCIAnalyzer, TravisFinding

INSECURE_TRAVIS = """
language: python
python:
  - python
env:
  API_SECRET: 'supersecret'
install:
  - curl -fsSL https://example.com/install.sh | bash
script:
  - sudo apt-get update
  - eval $SCRIPT
deploy:
  provider: ssh
  on:
    branch: main
"""

HARDENED_TRAVIS = """
language: python
python:
  - "3.12"
install:
  - pip install -e ".[dev]"
script:
  - python -m pytest
branches:
  only:
    - main
pull_request:
  branches:
    - main
"""


class TestTravisCIAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = TravisCIAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "no config" in analyzer.summary().lower()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(INSECURE_TRAVIS, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_usage" in kinds
        assert "dangerous_script" in kinds
        assert "ssh_deploy" in kinds
        assert "unpinned_language" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(HARDENED_TRAVIS, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.config_files == 1
        assert analyzer.infos[0].language == "python"

    def test_finding_format(self):
        finding = TravisFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".travis.yml",
            lineno=1,
            line="test line",
        )
        assert "[high]" in finding.format()
        assert ".travis.yml:1" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = TravisCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "language: python" in template
        assert "python -m pytest" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(INSECURE_TRAVIS, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Travis CI configuration analysis" in context
        assert "health score" in context
