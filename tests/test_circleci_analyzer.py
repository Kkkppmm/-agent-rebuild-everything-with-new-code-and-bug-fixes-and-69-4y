"""Tests for CircleCIAnalyzer."""

from pathlib import Path

from devai.circleci_analyzer import CircleCIAnalyzer, CircleFinding

INSECURE_CIRCLECI = """
version: 2.1
orbs:
  node: circleci/node
jobs:
  build:
    docker:
      - image: node:latest
    steps:
      - checkout
      - run:
          name: Install
          command: curl -fsSL https://example.com/install.sh | bash
      - run:
          name: Build
          command: eval $BUILD_SCRIPT
    environment:
      API_SECRET: 'supersecret'
"""

HARDENED_CIRCLECI = """
version: 2.1
orbs:
  python: circleci/python@2.1.0

jobs:
  test:
    docker:
      - image: cimg/python:3.12.0
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


class TestCircleCIAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = CircleCIAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "no config" in analyzer.summary().lower()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        config_dir = tmp_path / ".circleci"
        config_dir.mkdir()
        (config_dir / "config.yml").write_text(INSECURE_CIRCLECI, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert "dangerous_script" in kinds
        assert "latest_tag" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        config_dir = tmp_path / ".circleci"
        config_dir.mkdir()
        (config_dir / "config.yml").write_text(HARDENED_CIRCLECI, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.config_files == 1
        assert analyzer.infos[0].has_workflows

    def test_finding_format(self):
        finding = CircleFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".circleci/config.yml",
            lineno=1,
            line="test line",
        )
        assert "[high]" in finding.format()
        assert ".circleci/config.yml:1" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = CircleCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "version: 2.1" in template
        assert "python -m pytest" in template

    def test_to_context(self, tmp_path: Path):
        config_dir = tmp_path / ".circleci"
        config_dir.mkdir()
        (config_dir / "config.yml").write_text(INSECURE_CIRCLECI, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "CircleCI configuration analysis" in context
        assert "health score" in context
