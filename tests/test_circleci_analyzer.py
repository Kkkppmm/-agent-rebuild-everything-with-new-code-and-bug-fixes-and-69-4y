"""Tests for CircleCIAnalyzer."""

from pathlib import Path

from devai.circleci_analyzer import CircleCIAnalyzer, CircleCIFinding


INSECURE_CONFIG = """
version: 2.1

orbs:
  node: circleci/node
  deploy: my-org/deploy@volatile

jobs:
  build:
    docker:
      - image: node:latest
    steps:
      - checkout
      - run:
          name: Install
          command: curl -sSL http://install.example.com/setup.sh | bash
      - run:
          name: Build
          command: docker run -v /var/run/docker.sock:/var/run/docker.sock alpine echo ok
      - add_ssh_keys:
          fingerprints:
            - "aa:bb:cc"
    environment:
      API_TOKEN: "sk-live-hardcoded-secret"
"""

HARDENED_CONFIG = """
version: 2.1

orbs:
  python: circleci/python@2.1.1

jobs:
  test:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run:
          name: Run tests
          command: python -m pytest
"""


def _write_circleci(tmp_path: Path, content: str) -> Path:
    config_dir = tmp_path / ".circleci"
    config_dir.mkdir(parents=True)
    path = config_dir / "config.yml"
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
        assert "docker_socket_mount" in kinds
        assert "latest_image_tag" in kinds
        assert "unpinned_orb" in kinds or "floating_orb" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_circleci(tmp_path, HARDENED_CONFIG)
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_generate_hardened_template(self):
        snippet = CircleCIAnalyzer(".").generate_hardened_template()
        assert "version: 2.1" in snippet
        assert "security_scan" in snippet

    def test_finding_format(self):
        finding = CircleCIFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path=".circleci/config.yml",
            lineno=1,
        )
        assert ".circleci/config.yml:1" in finding.format()
