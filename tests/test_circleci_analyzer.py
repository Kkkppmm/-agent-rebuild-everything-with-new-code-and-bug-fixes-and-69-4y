"""Tests for CircleCIAnalyzer."""

from pathlib import Path

from devai.circleci_analyzer import CircleCIAnalyzer, CircleCIFinding

INSECURE_CONFIG = """
version: 2.1
orbs:
  python: circleci/python@dev
jobs:
  build:
    docker:
      - image: cimg/python:latest
        user: root
    environment:
      API_SECRET: supersecret
    steps:
      - checkout
      - run: curl -fsSL https://example.com/install.sh | bash
      - add_ssh_keys:
          fingerprints: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
"""

HARDENED_CONFIG = """
version: 2.1
orbs:
  python: circleci/python@2.1.1
jobs:
  test:
    docker:
      - image: cimg/python:3.12.7
        user: circleci
    steps:
      - checkout
      - python/install-packages:
          pkg-manager: pip
          app-dir: .
      - run: python -m pytest
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
        config_dir = tmp_path / ".circleci"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unpinned_orb" in kinds
        assert "latest_image" in kinds
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert "ssh_host_verification" in kinds
        assert "root_user" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        config_dir = tmp_path / ".circleci"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1
        assert len(analyzer.infos[0].jobs) >= 1

    def test_generate_template(self, tmp_path: Path):
        analyzer = CircleCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "version: 2.1" in template
        assert "python: circleci/python@" in template

    def test_to_context(self, tmp_path: Path):
        config_dir = tmp_path / ".circleci"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "CircleCI config analysis" in context
        assert "health score" in context

    def test_finding_format(self):
        finding = CircleCIFinding(
            kind="test",
            severity="high",
            message="test message",
            path="config.yml",
            lineno=1,
            job="build",
        )
        assert "build" in finding.format()
        assert "high" in finding.format()
