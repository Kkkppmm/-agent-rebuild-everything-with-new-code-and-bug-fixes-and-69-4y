"""Tests for GoCDCIAnalyzer."""

from pathlib import Path

from devai.gocd_ci_analyzer import GoCDCIAnalyzer, GoCDCIFinding


INSECURE_CONFIG = """
format_version: 10
pipelines:
  insecure-pipeline:
    group: defaultGroup
    environment_variables:
      API_TOKEN: "sk-live-hardcoded-secret"
      password: "supersecret123"
    materials:
      git:
        url: http://github.com/org/repo.git
        branch: main
        ignore_ssl: true
    stages:
      - build:
          jobs:
            build-job:
              tasks:
                - exec:
                    command: bash
                    arguments:
                      - -c
                      - curl -sSL http://install.example.com/setup.sh | bash
                - plugin:
                    configuration:
                      id: docker
                      version: 1
                      options:
                        image: ubuntu:latest
                        privileged: true
                        network_mode: host
                        run_as_user: 0
                        volumes:
                          - /var/run/docker.sock:/var/run/docker.sock
                          - /etc/passwd:/etc/passwd
                - exec:
                    command: bash
                    arguments:
                      - -c
                      - echo Deploying $GO_TRIGGER_USER on $GO_MATERIAL_BRANCH
"""

HARDENED_CONFIG = """
format_version: 10
pipelines:
  hardened-pipeline:
    group: defaultGroup
    environment_variables:
      PYTHON_VERSION: "3.12"
    materials:
      git:
        url: https://github.com/org/repo.git
        branch: main
        shallow_clone: true
    stages:
      - test:
          clean_workspace: true
          jobs:
            unit-tests:
              tasks:
                - exec:
                    command: bash
                    arguments:
                      - -c
                      - pip install -e '.[dev]' && python -m pytest

      - security-scan:
          jobs:
            scan:
              tasks:
                - exec:
                    command: bash
                    arguments:
                      - -c
                      - pip install devai && devai security-scan .
"""


def _write_gocd_config(tmp_path: Path, content: str) -> Path:
    gocd_dir = tmp_path / ".gocd"
    gocd_dir.mkdir()
    path = gocd_dir / "pipelines.yaml"
    path.write_text(content, encoding="utf-8")
    return path


class TestGoCDCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = GoCDCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_gocd_config(tmp_path, INSECURE_CONFIG)
        analyzer = GoCDCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "plaintext_env_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "host_network" in kinds
        assert "docker_socket_mount" in kinds
        assert "sensitive_volume" in kinds
        assert "script_injection" in kinds
        assert "latest_tag" in kinds
        assert "run_as_root" in kinds
        assert "insecure_skip_verify" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_gocd_config(tmp_path, HARDENED_CONFIG)
        analyzer = GoCDCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_gocd_config(tmp_path, HARDENED_CONFIG)
        analyzer = GoCDCIAnalyzer(str(tmp_path))
        assert "GoCD CI:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = GoCDCIAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "format_version:" in template
        assert "security-scan" in template

    def test_finding_format(self):
        finding = GoCDCIFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="pipelines.yaml",
            lineno=1,
        )
        assert "[high]" in finding.format()
