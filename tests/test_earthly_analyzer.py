"""Tests for EarthlyAnalyzer."""

from pathlib import Path

from devai.earthly_analyzer import EarthlyAnalyzer, EarthlyFinding


INSECURE_EARTHFILE = """\
VERSION 0.8

base:
    FROM ubuntu:latest
    ARG password=super-secret-password
    ARG api_key=sk-live-hardcoded-secret
    ENV db_password=another-secret-value
    RUN curl -s https://install.example.com/script.sh | bash
    RUN export token=hardcoded-token-value
    WITH DOCKER --privileged --insecure
        RUN --mount=type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock docker ps
    COPY /etc/passwd /tmp/passwd
    CACHE --id deps password=cache-secret
    SAVE IMAGE myapp:latest --push

prod:
    BUILD +base
    SAVE IMAGE registry.example.com/myapp+production:latest
"""

HARDENED_EARTHFILE = """\
VERSION 0.8

base:
    FROM alpine:3.20.3
    RUN apk add --no-cache ca-certificates
    USER nonroot:nonroot
    WORKDIR /app

build:
    FROM +base
    ARG --secret API_TOKEN
    COPY --chown=nonroot:nonroot . .
    RUN --mount=type=secret,id=API_TOKEN test -n "$API_TOKEN"
    SAVE ARTIFACT dist /dist

docker:
    FROM +build
    COPY +build/dist /app/dist
    SAVE IMAGE myapp:1.0.0
"""


class TestEarthlyAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = EarthlyAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Earthfile").write_text(INSECURE_EARTHFILE, encoding="utf-8")
        analyzer = EarthlyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "docker_socket_mount" in kinds
        assert "privileged_mode" in kinds
        assert "latest_tag" in kinds
        assert "plain_arg_secret" in kinds
        assert "sensitive_host_path" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "Earthfile").write_text(HARDENED_EARTHFILE, encoding="utf-8")
        analyzer = EarthlyAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "Earthfile").write_text(INSECURE_EARTHFILE, encoding="utf-8")
        analyzer = EarthlyAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, EarthlyFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "Earthfile").write_text(INSECURE_EARTHFILE, encoding="utf-8")
        analyzer = EarthlyAnalyzer(str(tmp_path))
        assert "Earthly configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Earthly analysis:" in context
        assert "targets:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = EarthlyAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "ARG --secret" in config
        assert "USER nonroot" in config

    def test_detects_earth_extension(self, tmp_path: Path):
        (tmp_path / "ci.earth").write_text(
            "VERSION 0.8\n\ntest:\n    FROM alpine:3.20.3\n    ARG token=secret\n",
            encoding="utf-8",
        )
        analyzer = EarthlyAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
        assert any(f.kind == "hardcoded_secret" for f in analyzer.analyze())
