"""Tests for ComposeAnalyzer."""

from pathlib import Path

from devai.compose_analyzer import ComposeAnalyzer, ComposeFinding

INSECURE_COMPOSE = """
version: "3.9"
services:
  app:
    image: nginx:latest
    privileged: true
    network_mode: host
    pid: host
    ports:
      - "6379:6379"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /:/host
    environment:
      API_SECRET: supersecret
    cap_add:
      - ALL
    security_opt:
      - seccomp:unconfined
"""

HARDENED_COMPOSE = """
services:
  app:
    image: python:3.12-slim
    user: "1000:1000"
    ports:
      - "127.0.0.1:8000:8000"
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
    networks:
      - backend

networks:
  backend:
    driver: bridge
"""


class TestComposeAnalyzer:
    def test_no_compose_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = ComposeAnalyzer(str(tmp_path))
        assert analyzer.stats.compose_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "docker-compose.yml").write_text(INSECURE_COMPOSE, encoding="utf-8")
        analyzer = ComposeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "pid_host" in kinds
        assert "latest_tag" in kinds
        assert "docker_sock_mount" in kinds
        assert "host_root_mount" in kinds
        assert "secret_in_environment" in kinds
        assert "cap_add_all" in kinds
        assert "unconfined_security_opt" in kinds
        assert "exposed_data_service" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_compose_scores_well(self, tmp_path: Path):
        (tmp_path / "compose.yaml").write_text(HARDENED_COMPOSE, encoding="utf-8")
        analyzer = ComposeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.compose_files == 1
        assert "app" in analyzer.infos[0].services

    def test_finding_format(self):
        finding = ComposeFinding(
            kind="privileged",
            severity="high",
            message="test",
            path="docker-compose.yml",
            lineno=5,
            service="app",
        )
        assert "app" in finding.format()
        assert "docker-compose.yml:5" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = ComposeAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "deploy:" in template
        assert "user:" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "docker-compose.yml").write_text(INSECURE_COMPOSE, encoding="utf-8")
        analyzer = ComposeAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Docker Compose Audit" in context
        assert "privileged" in context.lower() or "high" in context
