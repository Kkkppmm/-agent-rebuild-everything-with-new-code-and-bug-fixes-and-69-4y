"""Tests for TravisCIAnalyzer."""

from pathlib import Path

from devai.travis_ci_analyzer import TravisCIAnalyzer, TravisCIFinding

INSECURE_CONFIG = """
language: python
python:
  - python
env:
  global:
    - API_SECRET=supersecret
    - TOKEN=abc123
install:
  - curl -fsSL https://example.com/install.sh | bash
script:
  - sudo pip install -r requirements.txt
  - python -m pytest
deploy:
  provider: script
  script: deploy.sh
  skip_cleanup: true
  on:
    branch: main
"""

HARDENED_CONFIG = """
language: python
dist: jammy
python:
  - "3.12"
install:
  - pip install -e ".[dev]"
script:
  - python -m pytest
"""


class TestTravisCIAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_usage" in kinds
        assert "deploy_skip_cleanup" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1
        assert analyzer.infos[0].language == "python"

    def test_generate_template(self, tmp_path: Path):
        analyzer = TravisCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "language: python" in template
        assert "travis encrypt" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Travis CI config analysis" in context

    def test_finding_format(self):
        finding = TravisCIFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".travis.yml",
            lineno=1,
        )
        assert "high" in finding.format()
