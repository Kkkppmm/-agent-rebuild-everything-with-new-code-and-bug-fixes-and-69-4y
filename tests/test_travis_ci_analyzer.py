"""Tests for TravisCIAnalyzer."""

from pathlib import Path

from devai.travis_ci_analyzer import TravisCIAnalyzer, TravisCIFinding

INSECURE_TRAVIS = """
language: python
sudo: true
travis: true
docker: true
services:
  - docker
  - image: nginx:latest
env:
  global:
    API_SECRET: supersecret
    - secure: "abc123"
  matrix:
    - name: test-job
      env: DEPLOY_KEY=hardcoded
      allow_failure: true
script:
  - curl -fsSL https://example.com/install.sh | bash
  - wget -qO- https://travis-ci.org/script.sh | sh
addons:
  docker:
    privileged: true
"""

HARDENED_TRAVIS = """
language: python
python:
  - "3.12"
sudo: false
branches:
  only:
    - main
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
        (tmp_path / ".travis.yml").write_text(INSECURE_TRAVIS, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "sudo_enabled" in kinds
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert "untrusted_install_script" in kinds
        assert "privileged_docker" in kinds
        assert "unpinned_docker_image" in kinds
        assert "deprecated_travis" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(HARDENED_TRAVIS, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1
        assert analyzer.infos[0].language == "python"

    def test_finding_format(self):
        finding = TravisCIFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".travis.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert ".travis.yml:1" in finding.format()

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = TravisCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "language: python" in template
        assert "sudo: false" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(HARDENED_TRAVIS, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Travis CI analysis:" in context
        assert "health score" in context

    def test_travis_subdirectory(self, tmp_path: Path):
        travis_dir = tmp_path / ".travis"
        travis_dir.mkdir()
        (travis_dir / "ci.yml").write_text(HARDENED_TRAVIS, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
