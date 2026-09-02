"""Tests for CircleCIAnalyzer."""

from pathlib import Path

from devai.circleci_analyzer import CircleCIAnalyzer, CircleCIFinding


INSECURE_CONFIG = """
version: 2.1

orbs:
  node: circleci/node@latest

jobs:
  build:
    docker:
      - image: node:latest
    steps:
      - checkout
      - setup_remote_docker
      - run:
          name: Install
          command: curl -sSL http://install.example.com/setup.sh | bash
      - run:
          name: Build
          command: docker run --privileged alpine echo ok
      - run:
          name: Deploy
          command: echo Deploying $CIRCLE_BRANCH
    environment:
      API_TOKEN: "sk-live-hardcoded-secret"

  security_scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - run:
          name: Scan
          command: echo scan
          when: on_fail

workflows:
  ci:
    jobs:
      - build
      - security_scan
"""

HARDENED_CONFIG = """
version: 2.1

orbs:
  python: circleci/python@2.1.0

jobs:
  test:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run:
          name: Run tests
          command: python -m pytest

workflows:
  ci:
    jobs:
      - test
"""


def _write_circleci(tmp_path: Path, content: str) -> Path:
    circleci_dir = tmp_path / ".circleci"
    circleci_dir.mkdir()
    path = circleci_dir / "config.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestCircleCIAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_circleci(tmp_path, INSECURE_CONFIG)
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "latest_image_tag" in kinds
        assert "setup_remote_docker" in kinds
        assert "privileged_docker" in kinds
        assert "unpinned_orb" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_circleci(tmp_path, HARDENED_CONFIG)
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_circleci(tmp_path, HARDENED_CONFIG)
        analyzer = CircleCIAnalyzer(str(tmp_path))
        assert "CircleCI:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = CircleCIAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "version: 2.1" in template
        assert "security_scan" in template

    def test_finding_format(self):
        finding = CircleCIFinding(
            kind="test",
            severity="high",
            message="test message",
            path="config.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
