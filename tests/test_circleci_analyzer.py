"""Tests for CircleCIAnalyzer."""

from pathlib import Path

from devai.circleci_analyzer import CircleCIAnalyzer, CircleCIFinding

INSECURE_CIRCLECI = """
version: 2.1

orbs:
  python: circleci/python

jobs:
  test:
    docker:
      - image: node:latest
        privileged: true
    environment:
      API_SECRET: supersecret
      DEPLOY_TOKEN: hardcoded-token
    steps:
      - checkout
      - setup_remote_docker:
          docker_layer_caching: true
      - run:
          command: curl -fsSL https://example.com/install.sh | bash
      - add_ssh_keys:
          fingerprints:
            - "aa:bb:cc:dd"

  deploy:
    docker:
      - image: alpine
    steps:
      - run:
          command: ./deploy.sh

workflows:
  ci:
    jobs:
      - test
      - deploy:
          requires:
            - test
"""

HARDENED_CIRCLECI = """
version: 2.1

orbs:
  python: circleci/python@2.1.0

jobs:
  test:
    docker:
      - image: cimg/python:3.12.0
    environment:
      PIP_DISABLE_PIP_VERSION_CHECK: "1"
    steps:
      - checkout
      - run:
          name: Run tests
          command: python -m pytest

  hold:
    type: approval

workflows:
  ci:
    jobs:
      - test
"""


class TestCircleCIAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        circleci_dir = tmp_path / ".circleci"
        circleci_dir.mkdir()
        (circleci_dir / "config.yml").write_text(INSECURE_CIRCLECI, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_environment" in kinds
        assert "curl_pipe_shell" in kinds
        assert "unpinned_image" in kinds
        assert "privileged_container" in kinds
        assert "unpinned_orb" in kinds
        assert "setup_remote_docker" in kinds
        assert "add_ssh_keys" in kinds
        assert "ungated_deploy" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        circleci_dir = tmp_path / ".circleci"
        circleci_dir.mkdir()
        (circleci_dir / "config.yml").write_text(HARDENED_CIRCLECI, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1
        assert "test" in analyzer.infos[0].jobs

    def test_finding_format(self):
        finding = CircleCIFinding(
            kind="test",
            severity="high",
            message="example issue",
            path=".circleci/config.yml",
            lineno=10,
            line="privileged: true",
        )
        assert "[high]" in finding.format()
        assert "example issue" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = CircleCIAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "version: 2.1" in template
        assert "circleci/python@2.1.0" in template
        assert "cimg/python:3.12.0" in template

    def test_to_context_includes_score(self, tmp_path: Path):
        circleci_dir = tmp_path / ".circleci"
        circleci_dir.mkdir()
        (circleci_dir / "config.yml").write_text(HARDENED_CIRCLECI, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "CircleCI analysis:" in context
        assert "health score" in context
