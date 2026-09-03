"""Tests for TravisCIAnalyzer."""

from pathlib import Path

from devai.travis_ci_analyzer import TravisCIAnalyzer, TravisCIFinding


INSECURE_CONFIG = """
language: python

env:
  global:
    - API_TOKEN=sk-live-hardcoded-secret
    - DEPLOY_KEY=super-secret-key

sudo: required

services:
  - docker

before_install:
  - curl -sSL http://install.example.com/setup.sh | bash

script:
  - echo Building $TRAVIS_PULL_REQUEST_SLUG
  - docker pull myapp:latest

deploy:
  api_key: "AKIAIOSFODNN7EXAMPLE"
  provider: cloudfoundry
  skip_cleanup: true

jobs:
  include:
    - name: Security audit
      script: bandit -r .
      allow_failures: true
"""

HARDENED_CONFIG = """
language: python
python:
  - "3.12"

cache: pip

install:
  - pip install -e ".[dev]"

script:
  - python -m pytest

jobs:
  include:
    - name: Security scan
      script:
        - pip install devai
        - devai security-scan .
"""


def _write_travis_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / ".travis.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestTravisCIAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_travis_config(tmp_path, INSECURE_CONFIG)
        analyzer = TravisCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "api_key_deploy" in kinds
        assert "sudo_usage" in kinds
        assert "latest_tag" in kinds
        assert "script_injection" in kinds
        assert "skip_cleanup" in kinds
        assert "unpinned_language" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_travis_config(tmp_path, HARDENED_CONFIG)
        analyzer = TravisCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_travis_config(tmp_path, HARDENED_CONFIG)
        analyzer = TravisCIAnalyzer(str(tmp_path))
        assert "Travis CI:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = TravisCIAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "language: python" in template
        assert "Security scan" in template

    def test_finding_format(self):
        finding = TravisCIFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".travis.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
