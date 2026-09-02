"""Tests for BuildkiteAnalyzer."""

from pathlib import Path

from devai.buildkite_analyzer import BuildkiteAnalyzer, BuildkiteFinding


INSECURE_CONFIG = """
steps:
  - label: ":rocket: Build"
    command: curl -sSL http://install.example.com/setup.sh | bash
    env:
      API_TOKEN: "sk-live-hardcoded-secret"
    propagate_environment: true
    plugins:
      - docker#v5.8.0:
          image: myapp:latest
          privileged: true
          volumes:
            - /var/run/docker.sock:/var/run/docker.sock
    artifact_paths:
      - .env

  - label: "Deploy $BUILDKITE_BRANCH"
    command: echo Deploying $BUILDKITE_PULL_REQUEST

  - label: ":shield: Security audit"
    command: bandit -r .
    soft_fail: true

  - label: "Plugin test"
    plugins:
      - example/plugin#master
      - other/plugin#3
"""

HARDENED_CONFIG = """
steps:
  - label: ":pytest: Tests"
    command: python -m pytest
    agents:
      queue: default

  - label: ":shield: Security scan"
    command: |
      pip install devai
      devai security-scan .
    agents:
      queue: default
"""


def _write_buildkite_config(tmp_path: Path, content: str) -> Path:
    buildkite_dir = tmp_path / ".buildkite"
    buildkite_dir.mkdir()
    path = buildkite_dir / "pipeline.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestBuildkiteAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = BuildkiteAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_buildkite_config(tmp_path, INSECURE_CONFIG)
        analyzer = BuildkiteAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_docker" in kinds
        assert "docker_socket_mount" in kinds
        assert "propagate_environment" in kinds
        assert "sensitive_artifact" in kinds
        assert "script_injection" in kinds
        assert "unpinned_plugin" in kinds
        assert "security_soft_fail" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_buildkite_config(tmp_path, HARDENED_CONFIG)
        analyzer = BuildkiteAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_buildkite_config(tmp_path, HARDENED_CONFIG)
        analyzer = BuildkiteAnalyzer(str(tmp_path))
        assert "Buildkite:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = BuildkiteAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "steps:" in template
        assert "Security scan" in template

    def test_finding_format(self):
        finding = BuildkiteFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".buildkite/pipeline.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
