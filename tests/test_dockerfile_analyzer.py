"""Tests for DockerfileAnalyzer."""

from pathlib import Path

from devai.dockerfile_analyzer import DockerfileAnalyzer, DockerfileFinding


INSECURE_DOCKERFILE = """
FROM ubuntu:latest
ENV API_SECRET=supersecret
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://example.com/install.sh | bash
ADD . /app
EXPOSE 22
CMD ["python", "app.py"]
"""

HARDENED_DOCKERFILE = """
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc \\
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN adduser --disabled-password --gecos '' app
USER app
HEALTHCHECK CMD python -c "print('ok')"
EXPOSE 8000
CMD ["python", "-m", "app"]
"""


class TestDockerfileAnalyzer:
    def test_no_dockerfiles_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = DockerfileAnalyzer(str(tmp_path))
        assert analyzer.stats.dockerfiles == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text(INSECURE_DOCKERFILE, encoding="utf-8")
        analyzer = DockerfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "latest_tag" in kinds
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert "add_instead_of_copy" in kinds
        assert "runs_as_root" in kinds
        assert "apt_no_cleanup" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_dockerfile_scores_well(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text(HARDENED_DOCKERFILE, encoding="utf-8")
        analyzer = DockerfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.dockerfiles == 1
        assert analyzer.infos[0].has_user is True

    def test_finds_nested_dockerfiles(self, tmp_path: Path):
        deploy = tmp_path / "deploy"
        deploy.mkdir()
        (deploy / "api.Dockerfile").write_text("FROM alpine:3.19\nUSER nobody\n", encoding="utf-8")
        analyzer = DockerfileAnalyzer(str(tmp_path))
        assert analyzer.stats.dockerfiles == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text(HARDENED_DOCKERFILE, encoding="utf-8")
        analyzer = DockerfileAnalyzer(str(tmp_path))
        assert "Dockerfiles:" in analyzer.summary()
        assert "Dockerfile analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "USER app" in template
        assert "HEALTHCHECK" in template

    def test_finding_format(self):
        finding = DockerfileFinding(
            kind="latest_tag",
            severity="medium",
            message="uses :latest",
            path="Dockerfile",
            lineno=1,
        )
        assert "Dockerfile:1" in finding.format()
        assert "medium" in finding.format()
