"""Tests for ComposeAnalyzer."""

from pathlib import Path

from devai.compose_analyzer import ComposeAnalyzer, ComposeFinding


INSECURE_COMPOSE = """
version: "3.8"
services:
  web:
    image: nginx:latest
    privileged: true
    network_mode: host
    ports:
      - "0.0.0.0:80:80"
    environment:
      - API_SECRET=supersecret
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""

HARDENED_COMPOSE = """
version: "3.8"
services:
  web:
    image: nginx:1.25-alpine
    ports:
      - "127.0.0.1:8080:80"
    restart: unless-stopped
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
        assert "secret_in_env" in kinds
        assert "sensitive_volume" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_compose_scores_well(self, tmp_path: Path):
        (tmp_path / "compose.yaml").write_text(HARDENED_COMPOSE, encoding="utf-8")
        analyzer = ComposeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.services >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "docker-compose.yml").write_text(HARDENED_COMPOSE, encoding="utf-8")
        analyzer = ComposeAnalyzer(str(tmp_path))
        assert "Compose files:" in analyzer.summary()
        assert "Docker Compose analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = ComposeFinding(
            kind="privileged",
            severity="high",
            message="runs privileged",
            path="docker-compose.yml",
            lineno=5,
        )
        assert "docker-compose.yml:5" in finding.format()
