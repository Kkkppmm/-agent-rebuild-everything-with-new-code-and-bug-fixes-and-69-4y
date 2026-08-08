"""Tests for ComposeAnalyzer."""

from pathlib import Path

from devai.compose_analyzer import ComposeAnalyzer


INSECURE_COMPOSE = """
services:
  app:
    image: nginx:latest
    privileged: true
    network_mode: host
    user: root
    environment:
      API_SECRET: hardcoded-secret
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  worker:
    image: redis:latest
    cap_add:
      - ALL
"""

HARDENED_COMPOSE = """
services:
  app:
    image: python:3.12-slim
    user: "1000:1000"
    read_only: true
    cap_drop:
      - ALL
    environment:
      - DATABASE_URL=${DATABASE_URL}
    ports:
      - "8000:8000"
"""


class TestComposeAnalyzer:
    def test_no_compose_returns_perfect_score(self, tmp_path: Path):
        analyzer = ComposeAnalyzer(str(tmp_path))
        assert analyzer.stats.compose_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "docker-compose.yml").write_text(INSECURE_COMPOSE, encoding="utf-8")
        analyzer = ComposeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "latest_tag" in kinds
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "docker_sock_mount" in kinds
        assert "secret_in_env" in kinds
        assert "cap_add_all" in kinds
        assert analyzer.health_score() < 30.0

    def test_hardened_compose_scores_well(self, tmp_path: Path):
        (tmp_path / "docker-compose.yml").write_text(HARDENED_COMPOSE, encoding="utf-8")
        analyzer = ComposeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.services == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "compose.yaml").write_text(HARDENED_COMPOSE, encoding="utf-8")
        analyzer = ComposeAnalyzer(str(tmp_path))
        assert "Compose files:" in analyzer.summary()
        assert "Compose analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "cap_drop" in template
        assert "no-new-privileges" in template
