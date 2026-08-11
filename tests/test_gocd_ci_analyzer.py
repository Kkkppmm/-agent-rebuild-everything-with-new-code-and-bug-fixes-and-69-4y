"""Tests for GoCDCIAnalyzer."""

from pathlib import Path

from devai.gocd_ci_analyzer import GoCDCIAnalyzer, GoCDCIFinding


INSECURE_CONFIG = """
format_version: 10
pipelines:
  insecure-pipeline:
    group: default
    materials:
      git:
        git: http://insecure.example.com/repo.git
        branch: main
    stages:
      - stage: build
        jobs:
          deploy:
            tasks:
              - exec:
                  command: bash
                  arguments:
                    - -c
                    - "curl -sSL http://install.example.com/setup.sh | bash"
                    - "echo Building $GO_PIPELINE_NAME for $GO_TRIGGER_USER"
            environment_variables:
              API_TOKEN: "sk-live-hardcoded-secret"
              password: "supersecret123"
            docker:
              image: "library/ubuntu:latest"
              privileged: true
              network_mode: host
              volumes:
                - "/var/run/docker.sock:/var/run/docker.sock"
                - "/etc/passwd:/etc/passwd"
"""

HARDENED_CONFIG = """
format_version: 10
pipelines:
  hardened-pipeline:
    group: default
    materials:
      git:
        git: https://github.com/example/repo.git
        branch: release
        shallow_clone: true
    stages:
      - stage: test
        jobs:
          unit-test:
            tasks:
              - exec:
                  command: bash
                  arguments:
                    - -c
                    - "pip install -e '.[dev]' && python -m pytest"
      - stage: security-scan
        jobs:
          audit:
            tasks:
              - exec:
                  command: bash
                  arguments:
                    - -c
                    - "pip install devai && devai security-scan ."
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
        assert "curl_pipe_shell" in kinds
        assert "script_injection" in kinds
        assert "privileged_container" in kinds
        assert "docker_socket_mount" in kinds
        assert analyzer.stats.high_severity >= 5

    def test_hardened_config_has_fewer_findings(self, tmp_path: Path):
        _write_gocd_config(tmp_path, INSECURE_CONFIG)
        insecure = GoCDCIAnalyzer(str(tmp_path))
        insecure.analyze()

        hardened_path = tmp_path / "gocd.yaml"
        hardened_path.write_text(HARDENED_CONFIG, encoding="utf-8")
        hardened = GoCDCIAnalyzer(str(tmp_path))
        hardened.analyze()
        assert hardened.stats.findings < insecure.stats.findings

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = GoCDCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "format_version" in template
        assert "security-scan" in template

    def test_to_context(self, tmp_path: Path):
        _write_gocd_config(tmp_path, HARDENED_CONFIG)
        analyzer = GoCDCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "GoCD CI pipeline analysis" in context

    def test_finding_format(self):
        finding = GoCDCIFinding(
            kind="test",
            severity="high",
            message="test message",
            path="gocd.yaml",
            lineno=1,
        )
        assert "[high]" in finding.format()
